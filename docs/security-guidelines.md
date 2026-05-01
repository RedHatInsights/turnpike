# Security Guidelines

Rules and conventions for contributing to Turnpike, the nginx `auth_request` policy gateway.

## Architecture Invariants

1. Turnpike runs as an nginx `auth_request` subrequest handler. The `/auth/` location is marked `internal;` in nginx -- it must never be exposed externally. Do not add routes that would shadow or expose it.
2. The nginx config builder (`nginx/configuration_builder/build_config.py`) enforces that backend routes cannot start with the reserved segments `saml`, `auth`, or `_nginx` (`PROTECTED_ROUTES`). Never weaken this list.
3. Backend origins must resolve to a domain in `TURNPIKE_ALLOWED_ORIGIN_DOMAINS` (default: `.svc.cluster.local`). This prevents backends from proxying to arbitrary external hosts.
4. Every non-public backend must declare either an `auth` block or a `source_ip` block. Backends under `/public/` are the only ones allowed without access restrictions. The config builder rejects anything else at startup.

## Plugin Chain & PolicyContext

5. The policy chain order matters: VPN -> Auth -> SourceIP -> RHIdentity. VPN restriction is checked first; identity header enrichment happens last. Do not reorder without understanding the security implications.
6. A plugin that sets `context.status_code` short-circuits the chain -- no further plugins run and the response is returned immediately. Always set `status_code` (not just return early) when denying a request.
7. When the entire auth plugin chain completes without authenticating, `AuthPlugin` returns 401. Individual auth plugins should return the context unmodified (not set 401) when they simply do not apply -- the fallback handles the denial.
8. `PolicyContext.headers` is a mutable dict shared across all plugins. Only add headers you intend the upstream to see. The `X-RH-Identity` header is constructed by `RHIdentityPlugin` and forwarded via nginx `auth_request_set` directives.

## Authorization Predicates (eval)

9. The `saml`, `x509`, and `registry` auth plugins use `eval()` to evaluate backend authorization predicates from the YAML config. The predicate string (e.g., `'x509["subject_dn"].startswith("/CN=allowed")'`) is executed with a restricted namespace containing only the auth data dict. **Never** allow user-controlled input to flow into these predicates. They are trusted configuration, not request data.
10. OIDC backends do **not** use `eval()`. Authorization is determined by matching `clientId` and `scopes` from the JWT against the backend's `serviceAccounts` list.

## OIDC / JWT Authentication

11. JWT tokens are verified against JWKS keys fetched from the SSO OIDC provider. The JWKS response is cached for 24 hours (`timeout=86400` in `_get_jwks_keyset`). If you change caching behavior, ensure stale keys are still rotated.
12. The OIDC plugin validates these JWT claims as **essential**: `exp` (not expired) and `iss` (must match the configured issuer). The issuer URL intentionally omits the port (`self.issuer`) while the JWKS fetch URL includes it (`self.host`). Do not conflate them.
13. The `Authorization` header must use the `"Bearer "` prefix (capital B, trailing space) per RFC 6750. Tokens with other schemes are silently skipped, allowing downstream auth plugins to handle them.
14. Scope validation requires **all** configured scopes to be present in the token. A backend service account entry without a `scopes` field permits any scope set.
15. OIDC backend definitions are validated at boot time (`validate_oidc_definitions` in `__init__.py`). An empty `oidc` object, missing `clientId`, a `clientId` that is present but empty, or a `scopes` key that is present but empty (or contains empty strings) causes a startup failure. A service account entry with no `scopes` key at all is valid (means no scope restriction is enforced).

## X.509 / mTLS Authentication

16. X.509 auth requires both a valid subject header and a matching pre-shared key (PSK). The PSK check supports two secrets: `CDN_PRESHARED_KEY` (primary) and `CDN_PRESHARED_KEY_ALT` (rotation). When rotating CDN secrets, set the new value in `CDN_PRESHARED_KEY_ALT` first, then promote it.
17. The PSK header name is configurable via `HEADER_CERTAUTH_PSK`. If this config value is unset (`None`), or if the named header is absent from the request, `psk_check()` returns `False` and X.509 auth will never succeed.
18. Client certificate subject/issuer are passed via headers (`x-rh-certauth-cn`, `x-rh-certauth-issuer` by default) set by nginx after `ssl_verify_client`. These headers must only be set by the trusted nginx layer, never by external clients.

## Registry / Basic Auth Authentication

19. Registry auth sends credentials to an external service over mTLS (client cert + key required at startup). The response must contain `{"access": {"pull": "granted"}}` (additional fields in the response body are ignored; only `access.pull == "granted"` is checked).
20. Registry auth results are cached by `user:sha256(password)` with a configurable TTL (`REGISTRY_AUTH_CACHE_TTL`, default 300s). Changing a password invalidates the cache entry. All outbound requests enforce a timeout (`REGISTRY_SERVICE_TIMEOUT`, default 10s).
21. Basic Auth usernames use `org_id|username` format. The `|` delimiter is split with `maxsplit=1` to handle usernames that themselves contain the delimiter character.

## SAML Authentication

22. SAML session data is stored server-side in Redis via Flask-Session (`SESSION_TYPE = "redis"`). `SESSION_COOKIE_SECURE = True` is set unconditionally -- cookies are only sent over HTTPS.
23. The `MockSAMLAssertionView` (`/saml/.../mock/`) is gated by `TESTING` config. It returns 404 in non-test environments. Never set `TESTING=True` in production.
24. SAML has separate settings paths for "internal" and "private" IdPs (`INTERNAL_SAML_PATH`, `PRIVATE_SAML_PATH`). Each has its own certificate directory. Nginx routes 401 redirects to the correct SAML login based on the `X-Rh-Edge-Host` header value.

## VPN / Network Restrictions

25. VPN-restricted backends (`private: true`) require the `X-Rh-Edge-Host` header. This header is validated with a strict regex that only matches `(internal|private).(console|cloud).(stage|dev.)?redhat.com` with optional `mtls.` prefix.
26. Environment cross-contamination is blocked: a production host header is rejected in non-production, and vice versa. This is enforced in `HeaderValidator.validate_edge_host_header`.
27. Source IP filtering uses `X-Forwarded-For` with `HOPS_TO_EDGE` to determine the true client IP. Malformed hop lists result in 403. The `ProxyFix` middleware (`x_for=1`) is applied at the WSGI level.

## Secret Management

28. `SECRET_KEY` is required at import time of `config.py` -- the app refuses to start without it. Never commit it or any PSK/CDN secret to the repository.
29. `.gitignore` excludes `.env`, `dev-config.py`, `nginx/certs/`, `turnpike/saml/`, and `local/`. Keep credentials, certificates, and SAML configs out of version control.
30. The `SSO_OIDC_HOST`, `SSO_OIDC_PORT`, `SSO_OIDC_PROTOCOL_SCHEME`, and `SSO_OIDC_REALM` are all required at startup. Missing any of them raises `ValueError` and prevents boot.

## Header Security

31. `nginx/auth_request` passes only explicitly listed headers between nginx and the policy service. Headers the policy service needs are declared in each plugin's `headers_needed` set; headers to forward upstream are in `headers_to_forward`. If your plugin needs a new header, add it to the appropriate set.
32. The `/auth/` subrequest strips the request body (`proxy_pass_request_body off`). Auth decisions must be based solely on headers, session state, or cached data.
33. `X-RH-Identity` is base64-encoded JSON constructed by `RHIdentityPlugin`. It is never parsed from an incoming request header in the policy flow -- it is always generated fresh. The `/api/turnpike/identity/` endpoint does decode an incoming `X-Rh-Identity` for debugging but is itself behind auth.

## CI & Static Analysis

34. Pre-commit hooks enforce: `black` formatting, `trailing-whitespace`, `end-of-file-fixer`, `debug-statements` (no stray `breakpoint()`/`pdb`), and `mypy` type checking.
35. Container images are scanned on pushes and PRs targeting the `main`, `master`, or `security-compliance` branches via the `ConsoleDot Platform Security Scan` workflow using Anchore Grype (vulnerability scan) and Syft (SBOM generation). All three images (web, nginx, nginx-prometheus) are scanned independently.
36. Pin dependency versions in `Pipfile` (most packages use exact pins). Use `Pipfile.lock` for reproducible builds. The base image is UBI 9 minimal with a specific tag.

## Testing Auth Plugins

37. Test configurations must set `CACHE_TYPE: "SimpleCache"` (not Redis) and provide their own `SECRET_KEY`, `BACKENDS`, and plugin chains. Use `create_app(test_config)` with an explicit config dict -- never load the production `config.py` in tests.
38. Each auth plugin test should cover: skip when backend lacks the auth type, skip when credentials are absent, reject on invalid credentials, reject on insufficient authorization, and accept on valid credentials with matching predicates.
