# Performance Guidelines

Turnpike is an nginx `auth_request` subrequest handler. Every authenticated request to a backend triggers a subrequest to the Flask policy service before nginx proxies to the upstream. Latency in the policy service directly adds to every request's total latency.

## Architecture Constraints

- **Gunicorn runs 4 sync workers** (`run-server.sh`: `gunicorn -w 4`). Each worker handles one request at a time. Any blocking I/O in a plugin stalls that worker entirely.
- **nginx uses 1 worker process** with 1024 connections (`nginx.conf`). The auth subrequest is `internal` and uses `proxy_pass_request_body off` to avoid forwarding bodies to the policy service.
- **The policy chain is sequential.** Plugins in `PLUGIN_CHAIN` run in order (VPN, Auth, SourceIP, RHIdentity). The auth sub-chain (`AUTH_PLUGIN_CHAIN`) also runs sequentially (OIDC, Registry, SAML, X509). A slow plugin blocks all downstream plugins for that request.
- **Default resource limits** are 200m-500m CPU and 256Mi-512Mi memory for the web container (see `templates/web.yml`).

## Redis: Sessions and Cache

Redis backs two independent subsystems, both connecting to the same `REDIS_HOST`:

1. **Flask-Session** (`SESSION_TYPE = "redis"`): Stores SAML session data. Session lifetime is 4 hours (`PERMANENT_SESSION_LIFETIME = 60 * 60 * 4`).
2. **Flask-Caching** (`CACHE_TYPE = "RedisCache"`): Used by OIDC and Registry auth plugins for response caching.

Rules:
- Never use `flask.session` for caching auth decisions. Use the `cache` instance from `turnpike.cache` (a `flask_caching.Cache` object) with an explicit `timeout`.
- Always provide a `timeout` argument to `cache.set()`. Omitting it risks unbounded key growth.
- The session Redis connection is created at import time in `config.py` with no connection pooling configuration (`SESSION_REDIS = redis.Redis(...)`). Do not add per-request Redis connection creation.

## Caching Conventions

Two caching patterns exist in the codebase. Follow them exactly:

### OIDC JWKS Certificates (24-hour TTL)

The OIDC plugin caches the entire JWKS response under a single global key `oidc_jwks_response` with an 86400-second (24h) TTL. This avoids hitting the SSO server on every JWT-authenticated request.

```python
# In _get_jwks_keyset():
jwks_certificates = cache.get("oidc_jwks_response")
if not jwks_certificates:
    # ... fetch from SSO ...
    cache.set(key="oidc_jwks_response", value=jwks_certificates, timeout=86400)
```

- The cache key is static (shared across all workers/pods).
- When the SSO rotates keys, the 24h window is the maximum staleness.

### Registry Auth (5-minute TTL, per-credential)

The Registry plugin caches successful auth results per user+password-hash:

```python
cache_key = f"registry_auth:{user}:{password_hash}"
cache.set(key=cache_key, value=True, timeout=self.cache_ttl)
```

- `REGISTRY_AUTH_CACHE_TTL` defaults to 300 seconds (env-configurable).
- Password is SHA-256 hashed before inclusion in the cache key -- never store plaintext credentials in cache keys.
- Only successful auth results are cached. Failed attempts always hit the external registry service.

### Adding New Cached Data

When introducing a new cache entry:
1. Use a namespaced key prefix (e.g., `plugin_name:identifier`).
2. Always set an explicit `timeout`.
3. Test that the cache is hit on the second call (see `test_oidc_requests_get_cached` and `test_registry_requests_get_cached` for the pattern).
4. Use `SimpleCache` in test configs (`"CACHE_TYPE": "SimpleCache"`) to avoid requiring a Redis instance.

## External HTTP Calls

Only two plugins make outbound HTTP requests during policy evaluation:

| Plugin | Target | Timeout | Caching |
|--------|--------|---------|---------|
| `OIDCAuthPlugin` | SSO OIDC config + JWKS endpoint | **None set** (uses `requests` default) | 24h for JWKS |
| `RegistryAuthPlugin` | Registry service (mTLS) | `REGISTRY_SERVICE_TIMEOUT` (default 10s) | 5min per credential |

Rules:
- **Always set `timeout=` on `requests.get()` and `requests.post()` calls.** The OIDC plugin currently omits explicit timeouts on its HTTP calls. New plugins must not repeat this -- always pass a `timeout` parameter.
- The Registry plugin correctly uses `timeout=self.request_timeout`. Follow this pattern for any new external calls.
- Wrap all outbound calls in try/except. The OIDC plugin wraps all network and parsing failures into `UnableCreateKeysetError` inside `_get_jwks_keyset()`, then catches that domain exception in `process()` and returns 500. The Registry plugin catches `Exception` directly inline and returns 401. Either approach is acceptable; the critical requirement is that no exception escapes `process()`.

## Nginx Timeout and Buffering

Per-backend timeouts and buffering are configured in the backends YAML and applied via the nginx location template (`nginx_location_template.conf.j2`):

```yaml
- name: my-backend
  route: /api/my-service/
  origin: http://my-service.svc.cluster.local:8080/
  timeout: 90        # seconds; default is 60 (NGINX_DEFAULT_TIMEOUT_SECONDS)
  buffering: "off"   # "on" (default) or "off"
```

The timeout value applies to `send_timeout`, `client_body_timeout`, `proxy_read_timeout`, and `proxy_send_timeout` simultaneously.

Rules:
- Only increase `timeout` above 60s when the upstream genuinely needs it (e.g., long-running report endpoints). Document why.
- Set `buffering: "off"` only for streaming or SSE backends. Buffering is more efficient for typical request/response patterns.
- The auth subrequest location (`/auth/`) has custom buffer sizes: `proxy_buffer_size 16k`, `proxy_busy_buffers_size 24k`, `proxy_buffers 64 4k`. These accommodate large auth response headers (e.g., base64-encoded `X-RH-Identity`). Do not reduce these without testing with full SAML session data.

## DNS Resolution

Nginx resolves upstream hostnames using the system resolver with a 60-second cache (`resolver {{ resolver }} valid=60s`). This means DNS changes take up to 60 seconds to propagate. Do not lower `valid=` below 60s in production.

## Plugin Chain Performance

- Plugins that can short-circuit should do so early. The VPN plugin checks the `private` flag before any header validation. The Auth plugin skips entirely if no `auth` block is defined on the backend. Follow this pattern.
- Avoid adding logging at INFO or higher in the hot path. Use `DEBUG` level for per-request diagnostics. The root logger is set to `DEBUG` level, so ensure log volume is acceptable.
- The `match_by_backend_name` function does a linear scan of `BACKENDS`. For the current deployment scale (tens of backends), this is fine. If the backend count grows to hundreds, consider indexing by name.

## Metrics

- The `requests` counter (Prometheus) tracks `(service, policy_status_code)` labels. Keep cardinality low -- do not add high-cardinality labels (e.g., user IDs, request paths).
- Metrics are exposed via `/metrics` using `DispatcherMiddleware`. This endpoint is served by the same gunicorn workers. Do not add expensive computation to metric collection.
- The Grafana dashboard (`dashboards/grafana-dashboard-turnpike.configmap.yaml`) monitors CPU, memory, restarts, and request status code distribution for `web`, `nginx`, and `prometheus-nginx` containers.

## Health Checks

- Readiness and liveness probes hit `/_healthcheck/` on port 5000 with a 3-second timeout and 10-second period.
- The nginx health endpoint (`/_nginx/`) returns a static 200 with `access_log off` -- it adds no load.
- Do not add expensive operations (DB queries, external calls) to the healthcheck handler.

## Testing Considerations

- Test configs should use `"CACHE_TYPE": "SimpleCache"` to avoid Redis dependencies.
- Cache behavior tests must verify both cache-miss (first call hits external service) and cache-hit (second call does not) scenarios. See `test_oidc_requests_get_cached` and `test_registry_requests_get_cached`.
- When testing plugins that make external HTTP calls, mock at the `requests.get`/`requests.post` level, not at the cache level, to ensure caching logic is exercised.
