# Testing Guidelines

## Running Tests

```bash
# Run all tests (same as CI)
pytest --disable-pytest-warnings tests/

# Run a single test file
pytest tests/test_oidc_plugin.py

# Run a single test
pytest tests/test_oidc_plugin.py::TestMatchingBackends::test_missing_bearer_token
```

CI runs tests via `konflux-pr-check.sh` on Python 3.11 using `pytest`. Pre-commit hooks (black, mypy, trailing-whitespace, end-of-file-fixer, debug-statements) run separately in GitHub Actions.

## Test Framework and Style

- **unittest.TestCase** is the standard base class. Do not use bare pytest-style test functions (the one exception, `test_pending` in `test_app.py`, is a placeholder).
- Import `unittest` and use `self.assert*` methods for all assertions.
- Each test file covers one module or plugin. Name files `tests/test_<module>.py`.
- Every test method must have a docstring explaining intent.

## App Configuration Pattern

Tests create a real Flask app via `create_app(test_config)` with an inline config dict. There is no shared conftest.py or session-scoped app fixture. Each test class builds its own config in `setUp()` or a helper method.

Required minimum config keys for `create_app`:

```python
test_config = {
    "AUTH_DEBUG": True,
    "AUTH_PLUGIN_CHAIN": [
        "turnpike.plugins.x509.X509AuthPlugin",
        "turnpike.plugins.saml.SAMLAuthPlugin",
    ],
    "BACKENDS": yaml.safe_load(test_backends_file),  # or inline list
    "CACHE_TYPE": "SimpleCache",
    "DEFAULT_RESPONSE_CODE": http.HTTPStatus.INTERNAL_SERVER_ERROR,
    "HEADER_CERTAUTH_SUBJECT": "subject",
    "HEADER_CERTAUTH_ISSUER": "issuer",
    "HEADER_CERTAUTH_PSK": "test-psk",
    "PLUGIN_CHAIN": [
        "tests.mocked_plugins.mocked_plugin.MockPlugin",
    ],
    "SECRET_KEY": "12345",
    "TESTING": True,
}
```

- OIDC tests additionally require `SSO_OIDC_HOST`, `SSO_OIDC_PORT`, `SSO_OIDC_PROTOCOL_SCHEME`, and `SSO_OIDC_REALM` (accessed directly by `OIDCAuthPlugin.__init__` when instantiated via `AUTH_PLUGIN_CHAIN`).
- Registry tests additionally require `REGISTRY_SERVICE_URL`, `REGISTRY_SERVICE_CLIENT_CERT_PATH`, `REGISTRY_SERVICE_CLIENT_KEY_PATH`, and `REGISTRY_SERVICE_SSL_VERIFY`.
- When multiple test classes in the same process assert on log output, set `APP_NAME` to a unique value (e.g. `uuid.uuid4().__str__()`) to avoid log name collisions.

## Backend Fixtures

- YAML fixtures live in `tests/backends/`.
- `tests/backends/test-backends.yaml` is the primary shared fixture for valid backends.
- `tests/backends/invalid-configs/` contains one YAML file per invalid configuration scenario (e.g. `oidc-missing-client-id.yaml`). Each file is purpose-built for a single test.
- For simple tests, define backends inline as Python dicts rather than loading YAML.

## Mock Plugin

`tests/mocked_plugins/mocked_plugin.py` provides `MockPlugin`, a `TurnpikePlugin` subclass that captures the matched backend. Always include it in `PLUGIN_CHAIN` when you need to inspect which backend was matched:

```python
"PLUGIN_CHAIN": ["tests.mocked_plugins.mocked_plugin.MockPlugin"]
```

Access it via `self.app.config.get("PLUGIN_CHAIN_OBJS")[0]`.

## Mocking Conventions

### Flask request mocking

Two patterns are used depending on what is being tested:

1. **`mock.patch` the module-level `request`** -- used when testing plugin `.process()` methods directly (not through the Flask test client). This is the pattern used by `VPNPlugin` and `OIDCAuthPlugin` tests:
   ```python
   with mock.patch("turnpike.plugins.vpn.request", request_mock):
       plugin.process(context)
   ```

2. **`app.test_request_context()`** -- used when testing plugins that rely on Flask's request context proxy being active (e.g. `RegistryAuthPlugin`, `X509AuthPlugin`, `AuthPlugin`):
   ```python
   with self.app.test_request_context("/", headers=headers):
       result = self.plugin.process(context, backend_auth)
   ```

### External HTTP calls

Mock `requests.get` or `requests.post` at the plugin's module path. Use `side_effect` methods on the test class to simulate different server responses (success, error, unexpected status codes):

```python
get = mock.Mock(side_effect=self._requests_get_side_effect_success)
with mock.patch("turnpike.plugins.oidc.oidc.requests.get", get):
    ...
```

Define side effects as named methods on the test class (not lambdas) for reusability and readability.

### Mock objects

- Use `mock.Mock` (the class, not an instance) as a lightweight namespace to attach attributes to without call tracking: `context = mock.Mock` then `context.backend = {...}`. This pattern is used in OIDC and matcher tests.
- Use `mock.Mock()` (instance) when you need call counting or return value control.
- Use `PolicyContext()` (the real class, from `turnpike.plugin`) when you need a proper context object with typed attributes. This pattern is used in VPN, registry, and auth plugin tests.

### File I/O mocking

For nginx config builder tests, use `mock.mock_open()` to intercept file writes:
```python
with mock.patch("configuration_builder.build_config.open", open_mock, create=True):
    ...
```

## Log Assertions

Use `self.assertLogs(logger_name, level=...)` as a context manager to verify log output. The logger name is typically `self.app.logger.name` or `vpn_plugin.app.logger.name`. Check `cm.output[0]` (or specific indices) with `assertIn` or `assertTrue`.

## Test Organization by Module

| Test file | What it tests |
|---|---|
| `test_config.py` | Backend config validation at app startup (invalid OIDC configs) |
| `test_matcher.py` | Backend matching by name and by route URL |
| `test_oidc_plugin.py` | OIDC/JWT auth plugin (token validation, caching, error handling) |
| `test_registry_plugin.py` | Registry auth plugin (Basic Auth, mTLS, caching) |
| `test_vpn_plugin.py` | VPN edge-host header validation |
| `test_header_validator.py` | Edge host header classification (internal/private/prod) |
| `test_auth_plugin.py` | AuthPlugin fallback behavior when no plugin authenticates |
| `test_alternative_gateway_secret.py` | Alternative CDN pre-shared key acceptance |
| `test_backend_validations.py` | Nginx config builder route/origin validation |
| `test_nginx_config_builder.py` | Nginx location template rendering and file write order |
| `test_app.py` | Placeholder (single `pass` test) |

## sys.path Adjustments

Some test files append paths manually for the nginx config builder which lives outside the Python package:
```python
sys.path.append(os.path.abspath("./nginx"))
```
Tests must be run from the repository root directory for these relative paths to resolve.

## Formatting and Linting

- **black**: line length 119, target Python 3.11 (`black -l 119 -t py311`).
- **mypy**: configured in `mypy.ini` with `ignore_missing_imports = True`.
- Pre-commit hooks enforce both. CI in `konflux-pr-check.sh` also runs black as a gate.

## pytest Configuration

`pytest.ini` only suppresses `UserWarning`:
```ini
[pytest]
filterwarnings =
    ignore::UserWarning
```

No custom markers, plugins, or coverage requirements are configured. There is no coverage threshold enforced in CI.

## What to Test for New Plugins

1. **Skip behavior** -- plugin returns unmodified context when its auth type is absent from the backend.
2. **Missing/malformed input** -- missing headers, bad tokens, invalid credentials.
3. **External service errors** -- connection failures, unexpected status codes, invalid response bodies.
4. **Caching** -- verify that repeated calls with the same input do not re-call external services (check `mock.call_count`).
5. **Authorization predicate evaluation** -- when the backend has a predicate expression, test both pass and fail cases.
6. **Log output** -- verify that meaningful log messages are emitted for skip, deny, and error paths.
