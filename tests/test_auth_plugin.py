import http
import unittest
from http import HTTPStatus
from unittest import TestCase

import yaml

from turnpike import create_app
from turnpike.plugin import PolicyContext
from turnpike.plugins.auth import AuthPlugin


class TestAuthPluginFallback(TestCase):
    """Tests the AuthPlugin's fallback behavior when no auth plugin in the chain authenticates."""

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
        self.auth_plugin = AuthPlugin(self.app)

    def test_no_auth_required_returns_unmodified_context(self):
        """When the backend has no auth block, the context passes through unchanged."""
        context = PolicyContext()
        context.backend = {"name": "public-backend"}

        with self.app.test_request_context("/"):
            result = self.auth_plugin.process(context)

        self.assertIsNone(result.auth)
        self.assertIsNone(result.status_code)

    def test_fallback_returns_401_when_no_plugin_authenticates(self):
        """When all auth plugins skip and none authenticates, the fallback should return 401."""
        context = PolicyContext()
        context.backend = {
            "name": "registry-service",
            "auth": {"registry": "True"},
        }

        with self.app.test_request_context("/", headers={}):
            result = self.auth_plugin.process(context)

        self.assertIsNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.UNAUTHORIZED)

    def test_fallback_returns_401_for_saml_backend(self):
        """When all auth plugins skip on a SAML backend, the fallback should also return 401."""
        context = PolicyContext()
        context.backend = {
            "name": "saml-backend",
            "auth": {"saml": "True"},
        }

        with self.app.test_request_context("/", headers={}):
            result = self.auth_plugin.process(context)

        self.assertIsNone(result.auth)
        self.assertEqual(result.status_code, HTTPStatus.UNAUTHORIZED)
