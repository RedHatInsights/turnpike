from turnpike.views.views import policy_view
import http
import os
import sys
import unittest
import yaml

sys.path.append(os.path.abspath("./tests/mocked_plugins"))
sys.path.append(os.path.abspath("./turnpike"))

from turnpike import create_app
from unittest import mock
from turnpike.plugins.x509 import X509AuthPlugin


class TestMatchingBackends(unittest.TestCase):
    """Tests that the correct back ends are matched by Turnpike depending on what"s provided as an incoming header."""

    def setUp(self):
        """Set up a mocked Turnpike app."""
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
                "HEADER_CERTAUTH_PSK": "x-rh-insights-alt-gateway-secret",
                "PLUGIN_CHAIN": [
                    "tests.mocked_plugins.mocked_plugin.MockPlugin",
                ],
                "SECRET_KEY": "alt-gateway-secret",
            }

        self.app = create_app(test_config)
        self.app.config.update(
            {
                "TESTING": True,
            }
        )
        # Initialize the plugin instance for use in tests
        self.plugin = X509AuthPlugin(self.app)

    def test_accepts_alternative_gateway_secret(self):
        """When the special alt secret value is provided under the HEADER_CERTAUTH_PSK header name, psk_check should accept it."""
        headers = {
            self.plugin.cdn_psk: "alt-gateway-secret",
            self.plugin.subject_header: "CN=test",
        }
        with self.app.test_request_context("/", headers=headers):
            self.assertTrue(self.plugin.psk_check())

    def test_rejects_incorrect_alternative_value(self):
        """If the HEADER_CERTAUTH_PSK header is present but does not contain the alt secret nor the CDN_PRESHARED_KEY, psk_check should reject it."""
        headers = {
            self.plugin.cdn_psk: "wrong-secret",
            self.plugin.subject_header: "CN=test",
        }
        with self.app.test_request_context("/", headers=headers):
            self.assertFalse(self.plugin.psk_check())

    def test_accepts_cdn_preshared_key_when_configured(self):
        """If CDN_PRESHARED_KEY is configured and the header matches that value, psk_check should accept it."""
        self.app.config["CDN_PRESHARED_KEY"] = "shared-secret"
        headers = {
            self.plugin.cdn_psk: "shared-secret",
            self.plugin.subject_header: "CN=test",
        }
        with self.app.test_request_context("/", headers=headers):
            self.assertTrue(self.plugin.psk_check())
