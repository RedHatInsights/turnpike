# Error Handling Guidelines

## Architecture Context

Turnpike is an nginx `auth_request` subrequest handler. The `/auth/` endpoint returns empty-body responses with status codes that nginx interprets as allow/deny decisions. Plugins communicate outcomes by setting `context.status_code` on a `PolicyContext` object -- they never raise exceptions to signal authorization failure.

## Status Code Semantics

| Code | Meaning | Where Used |
|------|---------|------------|
| `None` | No decision yet; continue plugin chain | Default on `PolicyContext` |
| `200` | Request allowed (`DEFAULT_RESPONSE_CODE`) | End of plugin chain with no explicit decision |
| `401` | Authentication failed (no valid credentials) | `AuthPlugin` (no plugin authenticated), `OIDCAuthPlugin`, `RegistryAuthPlugin` |
| `403` | Forbidden (authenticated but unauthorized, or structurally invalid request) | `SAMLAuthPlugin`, `X509AuthPlugin`, `RegistryAuthPlugin`, `VPNPlugin`, `SourceIPPlugin`, unmatched route in `policy_view` |
| `500` | Internal infrastructure failure | `OIDCAuthPlugin` (keyset fetch failure), SAML ACS/SLS/Metadata views |
| `404` | Test-only guard | `MockSAMLAssertionView` when `TESTING` is falsy |
| `415` | Wrong content type | `MockSAMLAssertionView` for non-JSON |

Rules:

1. Use `HTTPStatus.UNAUTHORIZED` (401) when credentials are absent, malformed, expired, or the principal is not recognized at all.
2. Use `HTTPStatus.FORBIDDEN` (403) when the principal is authenticated but fails the authorization predicate (`eval(predicate, ...)`), or when the request is structurally rejected (wrong network, missing required header, IP not in allowlist).
3. Use `HTTPStatus.INTERNAL_SERVER_ERROR` (500) only for failures in Turnpike's own infrastructure (cannot reach SSO, cannot build JWKS keyset, SAML metadata invalid). Never use 500 for client-caused errors. Note: the Registry plugin is an exception -- it returns 401 (not 500) on connection failure to the registry service, treating the request as unauthenticated.
4. `policy_view` returns empty-body responses (`make_response("", status_code)`). Do not include error detail in the response body from the `/auth/` endpoint -- nginx does not forward it.

## Plugin Error-Flow Convention

Plugins must never raise exceptions to signal auth outcomes. The pattern is:

```python
# Set status_code and return -- do not raise
context.status_code = HTTPStatus.UNAUTHORIZED
return context
```

When `context.status_code` is set to any non-None value, the plugin chain short-circuits immediately in `policy_view`. When `context.auth` is set (successful authentication), the inner auth plugin chain inside `AuthPlugin` stops processing further auth plugins -- but the outer `PLUGIN_CHAIN` loop in `policy_view` continues running (it only short-circuits on `context.status_code`).

Auth plugins that do not handle a given auth type must return `context` unmodified (no status_code, no auth), allowing the next auth plugin to try.

## Startup Validation (Fail-Fast)

The application validates configuration at import/boot time and crashes intentionally on misconfiguration. There are two categories:

**`ValueError` -- missing required environment variables** (`config.py`, `registry.py`) **or invalid plugin class** (`turnpike/__init__.py`, `turnpike/plugins/auth.py`):
```python
if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set.")
```
Used for: `SECRET_KEY`, `SSO_OIDC_HOST`, `SSO_OIDC_PORT`, `SSO_OIDC_PROTOCOL_SCHEME`, `SSO_OIDC_REALM`, `REGISTRY_SERVICE_URL`, `REGISTRY_SERVICE_CLIENT_CERT_PATH`, `REGISTRY_SERVICE_CLIENT_KEY_PATH`. Also raised when a plugin class is not a valid `TurnpikePlugin` subclass (`turnpike/__init__.py`) or not a valid `TurnpikeAuthPlugin` subclass (`turnpike/plugins/auth.py`).

**`NotImplementedError` -- structurally invalid backend definitions** (`__init__.py:validate_oidc_definitions`):
Raised when OIDC backend configuration is incomplete (empty `oidc` object, empty `serviceAccounts` list, missing `clientId`, empty `scopes`). Also raised when no backends are configured at all.

**`InvalidBackendDefinitionError` -- nginx config builder** (`build_config.py`):
Custom exception for invalid routes (bad URL path, untrusted origin domain, protected route, missing both `auth` and `source_ip` blocks on a non-public route). Caught at the `main()` level and exits with code 1.

Rule: All new required configuration must follow the same pattern -- validate at startup, raise `ValueError` with a message naming the missing variable. Do not silently default required values.

## Custom Exception Classes

| Exception | Location | Purpose |
|-----------|----------|---------|
| `UnableCreateKeysetError` | `turnpike/plugins/oidc/unable_create_keyset_error.py` | Wraps all failures in JWKS keyset construction (network errors, unexpected status codes, parsing failures). Caught in `OIDCAuthPlugin.process()` and converted to 500. |
| `InvalidBackendDefinitionError` | `nginx/configuration_builder/build_config.py` | Backend route validation failures during nginx config generation. |

Rule: Domain-specific exceptions should be defined in their own module file (as `UnableCreateKeysetError` demonstrates). Internal helper methods raise the domain exception; the `process()` method catches it and sets the appropriate status code.

## Logging Conventions

The codebase uses Flask's `app.logger` (or `current_app.logger`) exclusively inside the application. The nginx config builder uses Python's standard `logging` module since it runs outside Flask.

**Log levels in practice:**

| Level | Usage |
|-------|-------|
| `debug` | Normal flow: plugin entry, skipping inapplicable plugins, successful operations |
| `info` | Plugin registration, VPN denials (for audit), SAML attribute debug (behind `AUTH_DEBUG` flag) |
| `warning` | Unexpected but client-attributable failures: malformed credentials, invalid response from upstream, unconfigured route matched, backend config missing optional `auth` |
| `error` | Infrastructure failures: cannot reach SSO/OIDC, registry request exception, invalid edge-host header value on VPN-restricted backend |
| `exception` | Used exactly once (`SourceIPPlugin`) for malformed `X-Forwarded-For` -- includes traceback |

Rules:

1. Prefer `logger.warning` for client-caused failures and `logger.error` for infrastructure failures. The registry plugin uses `logger.error` for connection failures to the registry service (which result in 401, not 500) -- this is an existing exception to the general pattern.
2. Use `logger.exception` (with traceback) only for truly unexpected errors, not for routine auth failures.
3. Sensitive data logging is gated behind the `AUTH_DEBUG` config flag. SAML attributes and x509 header values are only logged at `info` level when `AUTH_DEBUG` is truthy.
4. Log messages for VPN and header validation include a structured prefix: `[backend: "name"][header: "value"]`.
5. Never log passwords or bearer token values. The OIDC plugin logs token decode errors but not the token itself.

## SAML View Error Handling

SAML views (`ACSView`, `SLSView`, `MetadataView`) follow a distinct pattern from plugins because they are user-facing HTTP endpoints, not `auth_request` subrequests:

- **`ACSView` and `SLSView`**: check `saml_authentication.get_errors()` after processing. On error: return 500 with `text/plain` content type. The error reason is only included in the body when SAML debug mode is active (`is_debug_active()`); otherwise the body is empty.
- **`MetadataView`**: calls `settings.validate_metadata(metadata)`. On error: return 500 with the error list always included in the body (no `is_debug_active()` check; no explicit `Content-Type` override on the error response).
- On success: redirect (ACS, SLS) or return XML metadata (`Content-Type: text/xml`).

## External Service Failure Handling

When calling external services (SSO/OIDC, Registry), the pattern is:

1. Catch broad `Exception` from the `requests` call.
2. Log at `error` level with the exception message.
3. Set `context.status_code` to the appropriate HTTP status.
4. Return context immediately -- do not re-raise.

The OIDC plugin wraps all external call failures into `UnableCreateKeysetError` in the helper, then catches that single exception type in `process()` and sets 500. The Registry plugin handles each failure inline without a wrapper exception and sets 401 (not 500) on connection failure -- treating an unreachable registry as an authentication failure rather than an infrastructure error.

The nginx config builder retries the Flask service URL in a loop (`while not response_obj`) when it gets `URLError`, since Flask may still be starting. This is the only retry pattern in the codebase.

## Response Body Conventions

- `/auth/` endpoint: always empty body (`make_response("", status_code)`).
- `/api/turnpike/identity/`: returns JSON with either decoded identity or `{"error": "..."}`.
- `/api/turnpike/session/`: returns JSON with either session ID or `{"error": "..."}`.
- SAML views: return redirects on success, plain text error on failure (except `MetadataView`, which has no explicit `Content-Type` on its error response).
- `/_nginx_config/`: returns JSON, no error handling (assumes internal-only access).

## Authorization Predicate Errors

Backend auth predicates are evaluated via `eval(predicate, dict(...))`. If the predicate raises an exception, it propagates unhandled -- there is no try/except around `eval()` calls in `SAMLAuthPlugin`, `X509AuthPlugin`, or `RegistryAuthPlugin`. Predicate expressions must be valid Python that evaluates to a truthy/falsy value given the provided context dict.
