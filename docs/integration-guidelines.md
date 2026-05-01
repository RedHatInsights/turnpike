# Integration Guidelines

Rules and conventions for outbound HTTP calls, external service integration, and nginx interop in Turnpike.

## Architecture Overview

Turnpike operates as two containers: an **nginx reverse proxy** and a **Flask policy service**. Nginx delegates every auth decision to Flask via `auth_request /auth/`. Flask never proxies traffic itself; it only returns status codes (200, 401, 403) and response headers that nginx forwards to upstream backends.

## Outbound HTTP Call Conventions

### 1. Use `requests` for all outbound calls

All outbound HTTP calls use the `requests` library directly. There is no shared HTTP client, session pool, or wrapper. Each plugin instantiates its own calls.

### 2. No retry logic -- fail immediately

No plugin implements retries. When an outbound call fails (connection error, unexpected status code), the plugin logs the error and returns a failure status code on the `PolicyContext`. Do not add retry loops to auth-path calls; latency on the `auth_request` subrequest directly blocks the user's request in nginx.

### 3. Timeout conventions

| Integration point | Timeout | Source |
|---|---|---|
| Registry service POST | `REGISTRY_SERVICE_TIMEOUT` env var, default **10s** | `registry.py` constructor |
| OIDC well-known / JWKS GET | **None set** (uses `requests` default, which is unlimited) | `oidc.py` |
| Nginx upstream proxy | `timeout` per backend YAML entry, default **60s** | `build_config.py` `NGINX_DEFAULT_TIMEOUT` |

When adding a new outbound call, always pass an explicit `timeout=` to `requests`. The OIDC plugin's omission of a timeout is a known gap, not a pattern to follow.

### 4. Error handling: set `context.status_code`, never raise

Auth plugins must catch all exceptions from outbound calls internally. On infrastructure failure (cannot reach SSO, cannot reach registry), set `context.status_code` to `HTTPStatus.INTERNAL_SERVER_ERROR` or `HTTPStatus.UNAUTHORIZED` and return the context. Never let an exception propagate out of `process()`.

```python
# Correct pattern (from registry.py):
try:
    res = requests.post(url=self.registry_url, ..., timeout=self.request_timeout)
except Exception as e:
    self.app.logger.error(f"Registry authentication request failed: {e}")
    context.status_code = HTTPStatus.UNAUTHORIZED
    return context
```

### 5. Log at the right level

- `logger.error()` -- connection-level outbound call failures (cannot reach the external service at all)
- `logger.warning()` -- auth rejections where the caller provided credentials that were invalid, and unexpected but non-exception responses from external services (e.g., the registry service returning a non-200 status code)
- `logger.debug()` -- normal flow decisions (plugin skipped, cache hit, header inspection)

## Caching

### 6. Use `turnpike.cache` (Flask-Caching backed by Redis)

All cached values go through the `turnpike.cache` module, which is a `flask_caching.Cache` instance initialized with Redis in production and `SimpleCache` in tests.

### 7. Cache key and TTL conventions

| Cached data | Key pattern | TTL | Rationale |
|---|---|---|---|
| OIDC JWKS certificates | `oidc_jwks_response` (singleton) | **86400s (24h)** | Certificates rotate infrequently |
| Registry auth results | `registry_auth:{user}:{sha256(password)}` | `REGISTRY_AUTH_CACHE_TTL`, default **300s** | Avoid hammering registry on repeated requests |

Cache keys for per-user data must include a credential hash so that changed credentials cause a cache miss. See `registry.py` for the pattern using `hashlib.sha256`.

## mTLS Client Certificate Usage

### 8. Registry plugin: outbound mTLS via `cert=` parameter

The registry plugin authenticates to the external registry service using a client certificate. Paths are configured via `REGISTRY_SERVICE_CLIENT_CERT_PATH` and `REGISTRY_SERVICE_CLIENT_KEY_PATH` environment variables. The `verify` parameter is controlled by `REGISTRY_SERVICE_SSL_VERIFY`.

```python
requests.post(
    url=self.registry_url,
    json={"credentials": {"username": user, "password": password}},
    cert=(self.client_cert_path, self.client_key_path),
    verify=self.ssl_verify,
    timeout=self.request_timeout,
)
```

### 9. Inbound mTLS: handled by nginx, not Flask

Nginx terminates inbound client TLS and populates `x-rh-certauth-cn` / `x-rh-certauth-issuer` headers. The `X509AuthPlugin` reads these headers; it never touches certificates directly. A pre-shared key header (`HEADER_CERTAUTH_PSK` / `CDN_PRESHARED_KEY`) must also match for X.509 auth to succeed.

## OIDC / JWKS Integration

### 10. Two-step JWKS fetch: well-known then jwks_uri

The OIDC plugin first GETs `{host}/.well-known/openid-configuration`, extracts `jwks_uri` from the JSON response, then GETs that URI. Both calls use `requests.get()` with no timeout (see rule 3). The combined result is cached as a single key.

### 11. Issuer URL excludes port; host URL includes port

The `host` field (used for HTTP calls) includes the port: `{scheme}://{host}:{port}/auth/realms/{realm}`. The `issuer` field (used for JWT `iss` claim validation) excludes the port. Mixing these up will cause either connection failures or token validation failures.

## SAML Integration

### 12. SAML uses `python3-saml` (OneLogin), not outbound HTTP

SAML authentication is handled entirely through the `python3-saml` library and browser redirects. There are no outbound HTTP calls from the Flask process for SAML. The SSO interaction happens via the user's browser (302 redirects to SSO, POST back to `/saml/.../acs/`).

### 13. Dual SAML settings: internal vs. private

Two independent SAML configurations exist (`INTERNAL_SAML_PATH`, `PRIVATE_SAML_PATH`), selected by `SAMLSettingsType`. The nginx `@error401` handler determines which SAML login endpoint to redirect to based on the `X-Rh-Edge-Host` header.

## Nginx Integration

### 14. auth_request subrequest contract

Nginx sends `auth_request /auth/` for every proxied location. Flask responds with:
- **200** -- request is authorized; nginx forwards headers set in `context.headers` to the upstream
- **401** -- triggers `@error401` redirect to SAML login (only for SAML-enabled backends)
- **403** -- request is forbidden

Flask receives the original request URI via the `X-Original-Uri` header and the matched backend name via `X-Matched-Backend`.

### 15. Configuration builder startup sequence

The nginx container runs `build_config.py` at startup, which polls `{FLASK_SERVICE_URL}/_nginx_config/` in a retry loop (3-second sleep) until Flask is available. This endpoint returns the set of headers that plugins need forwarded. Nginx locations are generated from the backends YAML using Jinja2 templates.

### 16. Backend YAML `timeout` and `buffering` fields

Each backend entry supports optional `timeout` (integer seconds, default 60) and `buffering` (`"on"` or `"off"`, default `"on"`) fields. These control nginx `proxy_read_timeout`, `proxy_send_timeout`, `send_timeout`, `client_body_timeout`, and `proxy_buffering`/`proxy_request_buffering` for that location.

## Plugin Chain Conventions

### 17. Auth plugin chain: first match wins

The `AUTH_PLUGIN_CHAIN` is evaluated in order. The first plugin that sets `context.auth` (success) or `context.status_code` (failure) stops the chain. Plugins that do not recognize the request (wrong header, missing backend auth key) must return the context unmodified with `status_code=None` and `auth=None`.

### 18. Plugin initialization: validate config eagerly

Required configuration (URLs, cert paths, env vars) must be validated in `__init__`. The registry plugin raises `ValueError` for missing config. The OIDC backend definitions are validated at app startup in `validate_oidc_definitions()`. Fail at boot, not at request time.

## Testing Outbound Calls

### 19. Mock at the `requests` method level

Tests mock `requests.get` or `requests.post` via `unittest.mock.patch` at the module where they are imported. Use `side_effect` for conditional responses based on URL. Use `SimpleCache` (`CACHE_TYPE: "SimpleCache"`) in test configs to avoid requiring Redis.

### 20. Verify caching with call counts

Assert that repeated calls to a plugin with the same input do not increase the mock's `call_count`. See `test_oidc_requests_get_cached` and `test_registry_requests_get_cached` for the pattern.
