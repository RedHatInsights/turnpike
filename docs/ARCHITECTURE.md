# Architecture

This document explains the **why** behind Turnpike's design decisions. For operational rules and conventions, see the guideline documents referenced in AGENTS.md.

## Why nginx auth_request

Turnpike uses nginx's `auth_request` directive to delegate authentication decisions to a Flask sidecar rather than embedding auth logic in nginx itself or running Flask as a full reverse proxy.

The key insight is **separation of the data plane from the policy plane**. Nginx handles TLS termination, connection management, buffering, timeouts, and proxying — things it is extremely good at. Flask handles the policy decision — evaluating SAML sessions, verifying JWTs, checking mTLS headers, querying external registries — things that require complex logic, shared state (Redis sessions), and dynamic configuration. The `/auth/` subrequest carries no request body (`proxy_pass_request_body off`); the policy service sees only headers and returns only a status code with optional response headers.

The trade-off is startup coupling: nginx must wait for Flask to be ready before generating its config. `build_config.py` polls `/_nginx_config/` in a retry loop until Flask responds — the only retry pattern in the codebase.

## Why two containers (nginx + Flask)

Nginx and Flask are separate container images deployed as separate Kubernetes Deployments. Nginx needs minimal CPU/memory and handles many concurrent connections. Flask needs more CPU for cryptographic operations (JWT verification, SAML processing) but handles relatively few concurrent requests (4 Gunicorn sync workers). Separate Deployments let each scale independently.

The cost is network latency on the subrequest path — every authenticated request incurs an HTTP round-trip from nginx to Flask. This is acceptable because the policy service is in the same cluster (origin domain restriction enforces `.svc.cluster.local`).

## Why the plugin chain is dynamically loaded

`PLUGIN_CHAIN` and `AUTH_PLUGIN_CHAIN` are dotted Python class paths resolved via `importlib` at startup. Turnpike runs in multiple environments (stage, production, development) with different authentication requirements. Rather than maintaining environment-specific forks, the plugin chain is reconfigured per deployment via config values. A deployment can remove VPN enforcement or add a custom plugin without modifying source code.

The two-level chain design (outer `PLUGIN_CHAIN` with `AuthPlugin` orchestrating `AUTH_PLUGIN_CHAIN`) exists because authentication and policy enforcement are distinct concerns. VPN restriction and source-IP filtering are network-level checks that apply regardless of auth method. The auth sub-chain is "first match wins"; the outer chain is "run all unless short-circuited."

## Why PolicyContext carries shared state

Plugins receive a mutable `PolicyContext` rather than reading request headers directly, for three reasons:

1. **Short-circuit signaling**: Setting `context.status_code` stops the chain. This is the only early-termination mechanism.
2. **Cross-plugin data flow**: `RHIdentityPlugin` reads `context.auth` (set by whichever auth plugin succeeded) to build the `X-RH-Identity` header.
3. **Testability**: Tests construct a `PolicyContext`, pass it through a plugin, and inspect the result without a full HTTP request/response cycle.

## Why two SAML configurations (internal vs. private)

Turnpike serves two network audiences that authenticate against different SAML Identity Providers:

- **Internal** (`internal.console.redhat.com`): Red Hat corporate network, internal SSO.
- **Private** (`private.console.redhat.com`): VPN-only, separate SSO instance.

These are genuinely different IdPs. They cannot share a single SAML SP configuration because python3-saml validates that the IdP response's `Destination` matches the SP's configured hostname. The `@error401` nginx handler inspects `X-Rh-Edge-Host` to redirect unauthenticated users to the correct SAML login URL.

## Deployment context (OpenShift/Kubernetes)

- **ConfigMaps**: Backend route definitions, SAML IdP settings. Annotated with `qontract.recycle: "true"` so changes trigger pod restarts.
- **Secrets**: Flask `SECRET_KEY`, SAML SP cert/key, CDN pre-shared key (primary + alt for rotation), Redis endpoint, mTLS client cert for registry service.

The backends YAML (`/etc/turnpike/backends.yml`) is the single source of truth for routing — injected into both containers. Adding a backend is a ConfigMap change via app-interface merge request; no code change required.

## Known design gaps and constraints

**OIDC HTTP calls have no timeout.** `OIDCAuthPlugin` makes two `requests.get()` calls with no explicit `timeout`. A hanging SSO server blocks a Gunicorn worker indefinitely. The registry plugin correctly sets `timeout=self.request_timeout`. This gap has been documented but not fixed.

**Authorization predicates use `eval()`.** SAML, X.509, and registry auth plugins evaluate Python expressions from backends YAML via `eval()`. Safe only because predicates come from trusted configuration (app-interface MRs), never user input. An `eval()` error in a predicate propagates unhandled.

**No graceful JWKS key rotation detection.** JWKS certificates are cached for 24 hours. If SSO rotates keys, JWTs signed with the new key fail validation until the cache expires.

**Backend matching is linear.** Route lookup iterates all backends for the longest prefix match. Nginx's `X-Matched-Backend` header provides an exact name lookup on the common path.
