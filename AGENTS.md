# AGENTS.md

Turnpike is a Flask-based API gateway that acts as an nginx `auth_request` subrequest handler for Red Hat Insights. It evaluates authentication and authorization policies (SAML, OIDC/JWT, mTLS/X.509, Basic Auth via registry, VPN/source-IP) via a plugin chain, returning status codes that nginx uses to allow or deny proxied requests.

## Guideline Documents

Detailed domain-specific rules live in these files -- read them before making changes in their areas:

- `docs/security-guidelines.md` -- Plugin chain invariants, eval-based predicates, secret management, header trust boundaries
- `docs/performance-guidelines.md` -- Caching patterns (JWKS, registry), Redis usage, timeout conventions, Gunicorn/nginx tuning
- `docs/error-handling-guidelines.md` -- Status code semantics (200/401/403/500), plugin error-flow, startup validation, logging levels
- `docs/api-contracts-guidelines.md` -- Endpoint inventory, request/response headers, backend YAML schema, route matching rules
- `docs/testing-guidelines.md` -- Test framework (unittest.TestCase), app config pattern, mocking conventions, coverage expectations
- `docs/integration-guidelines.md` -- Outbound HTTP conventions, mTLS client certs, OIDC/JWKS fetch, nginx config builder startup

## Project Structure

```
turnpike/                  # Flask application package
  __init__.py              # create_app() factory, OIDC validation, blueprint registration
  config.py                # All env-var-driven configuration (loaded at import time)
  plugin.py                # PolicyContext, TurnpikePlugin, TurnpikeAuthPlugin base classes
  cache.py                 # Flask-Caching instance (Redis in prod, SimpleCache in tests)
  metrics.py               # Prometheus counter definition
  views/views.py           # /auth/, /identity/, /session/, /_nginx_config/ handlers
  views/saml/              # SAML blueprint views (login, acs, sls, metadata, mock)
  plugins/                 # Plugin implementations
    auth.py                # AuthPlugin -- orchestrates AUTH_PLUGIN_CHAIN
    vpn.py                 # VPN/edge-host enforcement
    source_ip.py           # Source IP CIDR allowlist
    rh_identity.py         # X-RH-Identity header construction
    oidc/oidc.py           # JWT/OIDC authentication
    registry.py            # Basic Auth against external registry service
    saml.py                # SAML session-based authentication
    x509.py                # mTLS/X.509 certificate authentication
    common/                # Shared utilities (HeaderValidator, AllowedNetworks)
nginx/                     # Nginx container
  configuration_builder/   # build_config.py -- generates nginx locations from backends YAML + Jinja2
  conf.d/                  # Static nginx config
tests/                     # unittest.TestCase-based tests; one file per module
  backends/                # YAML fixtures (valid and invalid backend configs)
  mocked_plugins/          # MockPlugin for test inspection
templates/                 # OpenShift deployment templates (web.yml, nginx.yml, prometheus-nginx.yml)
.tekton/                   # Konflux/Tekton CI pipeline definitions
scripts/                   # Dev convenience scripts
```

## Code Style and Formatting

- **Python 3.11** is the target runtime.
- **black** enforces formatting: line length 119, target py311 (`black -l 119 -t py311`).
- **mypy** runs with `ignore_missing_imports = True` (see `mypy.ini`).
- **Pre-commit hooks**: black, trailing-whitespace, end-of-file-fixer, debug-statements, mypy. Install with `pre-commit install`.
- Dependencies: **Pipfile/Pipfile.lock** (pipenv). Most packages are pinned exactly. Container build uses `micropipenv`.

## Architectural Patterns

- **Two-container model**: nginx (reverse proxy + TLS termination) and Flask (policy decisions only). Flask never proxies traffic.
- **Plugin chain via dynamic import**: `PLUGIN_CHAIN` and `AUTH_PLUGIN_CHAIN` are dotted Python class paths in `config.py`, imported at startup. Each must subclass `TurnpikePlugin` or `TurnpikeAuthPlugin`.
- **PolicyContext is the shared state object**: all plugins receive and return the same context. `context.status_code` short-circuits the outer chain; `context.auth` stops only the inner auth chain.
- **Config is module-level with fail-fast**: `config.py` executes at import time. Missing required env vars raise `ValueError` immediately.
- **Nginx config is generated at container startup**: `build_config.py` polls `/_nginx_config/` and renders Jinja2 templates. Plugin `headers_needed`/`headers_to_forward` declarations drive nginx config automatically.
- **Dual SAML configuration**: two independent IdP configs (internal vs. private) served under `/saml/internal/` and `/saml/private/` blueprints.

## CI/CD and Branching

- **Default branch**: `master`.
- **Konflux/Tekton pipelines** build three images: `turnpike-web`, `turnpike-nginx`, `turnpike-nginx-prometheus`.
- **PR checks**: `turnpike-web` runs black + pytest via `konflux-pr-check.sh`. Nginx pipelines build only.
- **GitHub Actions**: pre-commit, JSON/YAML validation, security scanning (Grype + Syft SBOM), bot PR labeling.
- **Dependency bumps** use `chore(deps):` commit prefix (MintMaker/Dependabot).

## Common Pitfalls

1. **`config.py` runs at import time** -- new required env vars crash on import, including test collection. Tests must pass a self-contained dict to `create_app(test_config)`.
2. **Tests must run from the repo root** -- nginx builder tests use relative `sys.path` appends.
3. **Auth predicates use `eval()`** -- SAML, X.509, and registry rules are Python expressions from YAML config. These are trusted configuration, never user-derived input.
4. **OIDC issuer vs host URL** -- `issuer` (for JWT `iss` validation) excludes port; `host` (for HTTP calls) includes it.
5. **No timeout on OIDC HTTP calls** -- known gap; all new outbound calls must include explicit `timeout=`.
6. **`/auth/` endpoint returns empty bodies** -- nginx ignores `auth_request` response bodies. Never put error details in `policy_view` responses.
7. **Backend list is scanned linearly** -- route matching and name lookup iterate all backends. Fine at current scale (tens of backends).
