# API Contracts Guidelines

## Architecture Overview

Turnpike is an nginx `auth_request` subrequest handler. Nginx intercepts every inbound request, sends an internal subrequest to `/auth/`, and the Flask policy service returns a status code (200, 401, 403, or 500) with optional response headers. Nginx then either proxies the original request to the upstream origin or rejects it.

## Endpoints

### Internal (nginx-only) endpoints

| Path | Method | Purpose | Response |
|---|---|---|---|
| `/auth/` | GET | Policy evaluation subrequest. Never called directly by clients. | Empty body; status code + headers |
| `/_healthcheck/` | GET | Liveness probe | JSON health status |
| `/_nginx_config/` | GET | Returns header-forwarding and blueprint metadata for the nginx config builder | JSON with `to_upstream`, `to_policy_service`, `blueprints` |
| `/metrics` | GET | Prometheus metrics (served via WSGI middleware, not Flask) | Prometheus text format |

### Client-facing endpoints

| Path | Method | Purpose | Response |
|---|---|---|---|
| `/api/turnpike/identity/` | GET | Decode and return the current `X-Rh-Identity` header | JSON identity object or `{"error": "..."}` |
| `/api/turnpike/session/` | GET | Return the current session cookie value | `{"session": "..."}` or `{"error": "..."}` |

### SAML endpoints (under `/saml/` blueprint)

Two parallel sets exist under `/saml/internal/` and `/saml/private/`, each bound to its own SAML IdP configuration.

| Path suffix | Method | Purpose |
|---|---|---|
| `/login/` | GET | Redirect to IdP; accepts `?next=` for post-login redirect |
| `/acs/` | POST | Assertion Consumer Service; processes IdP response, sets session, redirects to `RelayState` or `/` |
| `/metadata.xml` | GET | SP metadata (XML, `Content-Type: text/xml`) |
| `/sls/` | GET | Single Logout Service; clears session, redirects |
| `/mock/` | POST | Test-only; stores posted JSON as SAML assertion in session. Returns `204 No Content`. Requires `Content-Type: application/json`. Returns `404` when `TESTING` is not enabled, `415` for wrong content type. |

## Status Code Conventions

The `/auth/` endpoint returns only status codes with an empty body. Nginx interprets these to decide whether to proxy or reject.

| Code | Meaning | Set by |
|---|---|---|
| `200` | Request allowed (default when no plugin sets a code) | `DEFAULT_RESPONSE_CODE` config, end of plugin chain |
| `401` | Authentication failed (no plugin authenticated the request) | `AuthPlugin` fallback, `OIDCAuthPlugin` (bad/missing/expired token), `RegistryAuthPlugin` (credential or service failures) |
| `403` | Forbidden (authenticated but not authorized, or VPN/source-IP restriction failed) | `SAMLAuthPlugin`, `X509AuthPlugin`, `RegistryAuthPlugin` (predicate fails), `VPNPlugin`, `SourceIPPlugin` |
| `500` | Internal error (OIDC keyset fetch failure) | `OIDCAuthPlugin` |

Rules:
- A plugin sets `context.status_code` to short-circuit the chain; no further plugins run.
- If no plugin sets a status code and no plugin authenticates, `AuthPlugin` sets `401`.
- If no auth is required for the backend (no `auth` key), the request passes through to `DEFAULT_RESPONSE_CODE` (200).

## Request Headers (nginx to Flask)

These headers are set by nginx on the subrequest to `/auth/` and consumed by the Flask policy service.

| Header | Source | Purpose |
|---|---|---|
| `X-Original-URI` | `$request_uri` | The original client request URI; used for route matching when `X-Matched-Backend` is absent |
| `X-Matched-Backend` | `$matched_backend` (set per-location) | Backend name matched by nginx; preferred over URI-based matching |
| `X-Rh-Edge-Host` | Upstream edge proxy | Identifies network origin (`internal` vs `private`); validated by `VPNPlugin` against regex |
| `X-Forwarded-For` | Standard proxy header | Used by `SourceIPPlugin` to extract client IP (hop count configured via `HOPS_TO_EDGE`) |
| `X-Forwarded-Host` | `$host` | Forwarded to Flask; used by `ProxyFix` middleware |
| `X-Forwarded-Port` | Hardcoded `443` | Always set to 443 |
| `X-Forwarded-Proto` | Hardcoded `https` | Always set to https |
| `Authorization` | Client | Consumed by `OIDCAuthPlugin` (`Bearer` scheme) and `RegistryAuthPlugin` (`Basic` scheme) |
| `x-rh-certauth-cn` | mTLS gateway (configurable via `HEADER_CERTAUTH_SUBJECT`) | X.509 client certificate subject DN |
| `x-rh-certauth-issuer` | mTLS gateway (configurable via `HEADER_CERTAUTH_ISSUER`) | X.509 client certificate issuer DN |
| PSK header | mTLS gateway (name configurable via `HEADER_CERTAUTH_PSK`) | Pre-shared key for CDN/gateway certificate validation |

Plugins declare which headers they need via `headers_needed` (forwarded to the policy service) and `headers_to_forward` (forwarded from the policy response to the upstream origin). The nginx config builder dynamically generates `proxy_set_header` directives from these sets.

## Response Headers (Flask to upstream)

| Header | Set by | Content |
|---|---|---|
| `X-RH-Identity` | `RHIdentityPlugin` | Base64-encoded JSON identity object; forwarded by nginx to the upstream origin |

The `X-RH-Identity` payload structure depends on the authentication method:

- **SAML** (`type: "Associate"`, `auth_type: "saml-auth"`): Contains user attributes from the SAML assertion (e.g., `Role`, `email`, `givenName`, `rhatUUID`, `surname`).
- **X.509** (`type: "X509"`, `auth_type: "X509"`): Contains `subject_dn` and `issuer_dn`.
- **OIDC** (`type: "Service_Account"`, `auth_type: "oidc-service-account"`): Contains `client_id`, `preferred_username`, and `scopes`.
- **Registry** (`type: "Registry"`, `auth_type: "registry-auth"`): Contains `org_id` and `username`.

## Backend Configuration Contract

Backends are defined in a YAML list (loaded from `BACKENDS_CONFIG_MAP`). Each entry must conform to:

```yaml
- name: my-service              # Required. Unique string identifier.
  route: /api/my-service/       # Required. URL prefix for matching. Must start with /.
  origin: http://svc.cluster.local:8080/  # Required. Proxy target. Must be in an allowed domain.
  private: false                # Optional. VPN-restricted if true. Default: false.
  timeout: 60                   # Optional. Nginx timeout in seconds. Default: 60.
  buffering: "on"               # Optional. "on" or "off". Default: "on".
  source_ip:                    # Optional. List of allowed CIDR blocks.
    - 10.0.0.0/8
  auth:                         # Optional. If absent, no auth required (route must be under /public/).
    saml: "True"                # Python expression evaluated with `user` dict.
    x509: "True"                # Python expression evaluated with `x509` dict.
    oidc:                       # OIDC service account definitions.
      serviceAccounts:
        - clientId: <uuid>      # Required within each SA entry.
          scopes:               # Optional. All listed scopes must be present in token.
            - scope_a
    registry: "True"            # Python expression evaluated with `registry` dict.
```

Validation rules enforced at startup and by the nginx config builder:
- Routes must start with `/` and be a valid URL path.
- Origins must be in a domain from `TURNPIKE_ALLOWED_ORIGIN_DOMAINS` (default: `.svc.cluster.local`).
- Routes under `saml`, `auth`, `_nginx` are reserved and rejected.
- First path segment must be in `TURNPIKE_ALLOWED_ROUTES` (default: `public`, `api`, `app`) or start with `_`.
- Routes without `auth` or `source_ip` must have their first segment in `TURNPIKE_NO_AUTH_ROUTES` (default: `public`).
- OIDC backends: every `serviceAccounts` entry must have a non-empty `clientId`; `scopes` if present must be a non-empty list with no empty strings.

## Route Matching

1. If nginx sends `X-Matched-Backend`, Turnpike looks up the backend by `name` (exact match).
2. Otherwise, Turnpike matches by longest `route` prefix against `X-Original-URI`.
3. If no backend matches, the response is `403` (indicates a configuration mismatch).

## Plugin Chain

Plugins execute in `PLUGIN_CHAIN` order. The default chain is:

1. **VPNPlugin** -- Rejects requests to `private: true` backends unless `X-Rh-Edge-Host` indicates the private network.
2. **AuthPlugin** -- Runs the `AUTH_PLUGIN_CHAIN` (OIDC, Registry, SAML, X509) in order. First plugin to authenticate wins. If none authenticates, returns 401.
3. **SourceIPPlugin** -- Enforces `source_ip` CIDR allowlists using `X-Forwarded-For`.
4. **RHIdentityPlugin** -- Constructs and attaches the `X-RH-Identity` header from auth data.

Auth plugin processing: each auth plugin checks whether its auth type key exists in the backend's `auth` dict. If absent, it skips. If present, it attempts authentication. On success it sets `context.auth`; on authorization failure (predicate evaluates to `False`) it sets `context.status_code = 403`.

## SAML Login Redirect Flow

When a backend with `saml` auth returns `401`, nginx's `error_page 401 = @error401` redirects the client to the appropriate SAML login page:
- Internal network: `https://{INTERNAL_HOSTNAME}/saml/internal/login/?next=$request_uri`
- Private/VPN network (detected via `X-Rh-Edge-Host` containing "private"): `https://{PRIVATE_HOSTNAME}/saml/private/login/?next=$request_uri`

Only backends with `saml` in their `auth` block get the `error_page 401` directive.

## Metrics

A single Prometheus counter `requests` is tracked with labels `service` (backend name) and `policy_status_code`.
