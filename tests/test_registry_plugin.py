import base64
import http
import unittest
from http import HTTPStatus
from unittest import TestCase, mock

import yaml

from turnpike import create_app
from turnpike.plugin import PolicyContext
from turnpike.plugins.registry import RegistryAuthPlugin


class TestRegistryAuthPlugin(TestCase):

    def setUp(self):
        with open("./tests/backends/test-backends.yaml") as test_backends_file:
            test_config = {
                "AUTH_DEBUG": True,
                "AUTH_PLUGIN_CHAIN": [
                    "turnpike.plugins.x509.X509AuthPlugin",
                    "turnpike.plugins.saml.SAMLAuthPlugin",
                ],
                "BACKENDS": yaml.safe_load(test_backends_file),
                "CACHE_TYPE": "SimpleCache",
                "DEFAULT_RESPONSE_CODE": http.HTTPStatus.INTERNAL_SERVER_ERROR,
                "HEADER_CERTAUTH_SUBJECT": "subject",
                "HEADER_CERTAUTH_ISSUER": "issuer",
                "HEADER_CERTAUTH_PSK": "test-psk",
                "PLUGIN_CHAIN": [
                    "tests.mocked_plugins.mocked_plugin.MockPlugin",
                ],
                "SECRET_KEY": "test-secret",
                "TESTING": True,
                "REGISTRY_SERVICE_URL": "https://registry.example.com/auth",
                "REGISTRY_SERVICE_CLIENT_CERT_PATH": "/tmp/test-cert.pem",
                "REGISTRY_SERVICE_CLIENT_KEY_PATH": "/tmp/test-key.pem",
                "REGISTRY_SERVICE_SSL_VERIFY": True,
            }

        self.app = create_app(test_config)
        self.plugin = RegistryAuthPlugin(self.app)

    def _find_registry_backend(self):
        for backend in self.app.config["BACKENDS"]:
            if backend["name"] == "registry-service":
                return backend
        raise Exception("unable to find the registry backend")

    def _make_basic_auth_header(self, user, password):
        credentials = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("utf-8")
        return f"Basic {credentials}"

    def _make_context(self):
        context = PolicyContext()
        context.backend = self._find_registry_backend()
        return context

    def _mock_post_side_effect(self, status_code=200, json_data=None):
        """Create a fresh mock response side effect to avoid shared state pollution"""

        def side_effect(*args, **kwargs):
            response = mock.Mock()
            response.status_code = status_code
            if json_data is not None:
                response.json.return_value = json_data
            else:
                response.json.return_value = {"access": {"pull": "granted"}}
            return response

        return side_effect

    def test_skip_when_registry_not_in_backend_auth(self):
        context = PolicyContext()
        context.backend = {"name": "other", "auth": {"saml": "True"}}
        backend_auth = context.backend["auth"]

        result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertIsNone(result.status_code)

    def test_skip_when_no_authorization_header(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]

        with self.app.test_request_context("/", headers={}):
            result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertIsNone(result.status_code)

    def test_skip_when_authorization_is_bearer(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": "Bearer some-jwt-token"}

        with self.app.test_request_context("/", headers=headers):
            result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertIsNone(result.status_code)

    def test_successful_authentication(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        post = mock.Mock(side_effect=self._mock_post_side_effect())
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        self.assertIsNotNone(result.auth)
        self.assertEqual(result.auth["auth_data"]["org_id"], "123")
        self.assertEqual(result.auth["auth_data"]["username"], "alice")
        self.assertEqual(result.auth["auth_plugin"], self.plugin)
        self.assertIsNone(result.status_code)

    def test_registry_returns_non_200(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        post = mock.Mock(side_effect=self._mock_post_side_effect(status_code=403))
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.UNAUTHORIZED)

    def test_registry_returns_invalid_response_body(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        response = mock.Mock()
        response.status_code = 200
        response.json.side_effect = ValueError("invalid json")

        post = mock.Mock(return_value=response)
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.UNAUTHORIZED)

    def test_registry_returns_pull_not_granted(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        post = mock.Mock(side_effect=self._mock_post_side_effect(json_data={"access": {"pull": "denied"}}))
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.UNAUTHORIZED)

    def test_mtls_cert_key_passed_to_requests(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        post = mock.Mock(side_effect=self._mock_post_side_effect())
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                self.plugin.process(context, backend_auth)

        post.assert_called_once()
        call_kwargs = post.call_args
        self.assertEqual(call_kwargs.kwargs["cert"], ("/tmp/test-cert.pem", "/tmp/test-key.pem"))
        self.assertEqual(call_kwargs.kwargs["verify"], True)

    def test_malformed_base64_credentials(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": "Basic !!!not-valid-base64!!!"}

        with self.app.test_request_context("/", headers=headers):
            result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.UNAUTHORIZED)

    def test_authorization_predicate_fails(self):
        context = PolicyContext()
        context.backend = {
            "name": "restricted-registry",
            "auth": {"registry": 'registry["org_id"] == "999"'},
        }
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        post = mock.Mock(side_effect=self._mock_post_side_effect())
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        self.assertIsNotNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.FORBIDDEN)

    def test_request_exception_returns_unauthorized(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        post = mock.Mock(side_effect=Exception("connection refused"))
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.UNAUTHORIZED)

    def test_username_without_pipe_delimiter(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("plainuser", "secret")}

        post = mock.Mock(side_effect=self._mock_post_side_effect())
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        self.assertIsNotNone(result.auth)
        self.assertIsNone(result.auth["auth_data"]["org_id"])
        self.assertIsNone(result.auth["auth_data"]["username"])

    def test_missing_registry_url_raises_value_error(self):
        config = self.app.config.copy()
        config["REGISTRY_SERVICE_URL"] = None
        app = create_app(config)
        with self.assertRaises(ValueError):
            RegistryAuthPlugin(app)

    def test_missing_client_cert_raises_value_error(self):
        config = self.app.config.copy()
        config["REGISTRY_SERVICE_CLIENT_CERT_PATH"] = None
        app = create_app(config)
        with self.assertRaises(ValueError):
            RegistryAuthPlugin(app)

    def test_missing_client_key_raises_value_error(self):
        config = self.app.config.copy()
        config["REGISTRY_SERVICE_CLIENT_KEY_PATH"] = None
        app = create_app(config)
        with self.assertRaises(ValueError):
            RegistryAuthPlugin(app)

    def test_credentials_with_colon_in_password(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "p:a:s:s")}

        post = mock.Mock(side_effect=self._mock_post_side_effect())
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        call_kwargs = post.call_args
        body = call_kwargs.kwargs["json"]
        self.assertEqual(body["credentials"]["password"], "p:a:s:s")
        self.assertIsNotNone(result.auth)

    def test_response_missing_access_key(self):
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        post = mock.Mock(side_effect=self._mock_post_side_effect(json_data={"status": "ok"}))
        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                result = self.plugin.process(context, backend_auth)

        self.assertIsNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.UNAUTHORIZED)

    def test_registry_requests_get_cached(self):
        """Tests that we only call the registry service once for the same user due to caching."""
        # Set up the test context and backend auth
        context = self._make_context()
        backend_auth = context.backend["auth"]
        headers = {"Authorization": self._make_basic_auth_header("123|alice", "secret")}

        # Mock successful registry auth response
        json_data = {"access": {"pull": "granted"}}
        post = mock.Mock(side_effect=self._mock_post_side_effect(json_data=json_data))

        with self.app.test_request_context("/", headers=headers):
            with mock.patch("turnpike.plugins.registry.requests.post", post):
                # First call should hit the external API
                result1 = self.plugin.process(context, backend_auth)

                # Ensure the call was successful
                self.assertIsNotNone(result1.auth)
                self.assertEqual(result1.status_code, None)  # No error status code set

                # Verify external API was called once
                self.assertEqual(1, post.call_count)

                # Second call with same user should use cache
                result2 = self.plugin.process(context, backend_auth)

                # Ensure the second call was also successful
                self.assertIsNotNone(result2.auth)
                self.assertEqual(result2.status_code, None)

                # Verify external API was still only called once (cache hit)
                self.assertEqual(1, post.call_count)

    def test_registry_cache_ttl_configurable(self):
        """Tests that cache TTL can be configured via REGISTRY_AUTH_CACHE_TTL."""
        # Test with custom TTL
        custom_ttl = 600  # 10 minutes
        with self.app.test_request_context():
            with self.app.app_context():
                self.app.config["REGISTRY_AUTH_CACHE_TTL"] = custom_ttl
                plugin = RegistryAuthPlugin(self.app)

                # Verify the plugin uses the configured TTL
                self.assertEqual(plugin.cache_ttl, custom_ttl)
