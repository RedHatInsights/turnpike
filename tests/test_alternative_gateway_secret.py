import os
import sys
import http
import unittest
import yaml

sys.path.append(os.path.abspath("./tests/mocked_plugins"))
sys.path.append(os.path.abspath("./turnpike"))

from turnpike import create_app
from turnpike.plugins.x509 import X509AuthPlugin


class TestX509PSKAlt(unittest.TestCase):
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
                # HEADER_CERTAUTH_PSK is the header name that carries the PSK value
                "HEADER_CERTAUTH_PSK": "x-rh-insights-gateway-secret",
                # CDN_PRESHARED_KEY_ALT holds the alternative secret value to accept
                "CDN_PRESHARED_KEY_ALT": "alt-gateway-secret",
                "PLUGIN_CHAIN": [
                    "tests.mocked_plugins.mocked_plugin.MockPlugin",
                ],
                "SECRET_KEY": "test-secret",
            }

        self.app = create_app(test_config)
        self.app.config.update({"TESTING": True})
        self.plugin = X509AuthPlugin(self.app)

    def test_accepts_alternative_cdn_preshared_key_alt(self):
        """When the main PSK header value equals CDN_PRESHARED_KEY_ALT, psk_check should accept it."""
        headers = {
            self.plugin.cdn_psk: "alt-gateway-secret",
            self.plugin.subject_header: "CN=test",
        }
        with self.app.test_request_context("/", headers=headers):
            self.assertTrue(self.plugin.psk_check())

    def test_rejects_when_value_does_not_match_any_secret(self):
        """If the PSK header value does not match CDN_PRESHARED_KEY or CDN_PRESHARED_KEY_ALT, psk_check should reject."""
        headers = {
            self.plugin.cdn_psk: "wrong-secret",
            self.plugin.subject_header: "CN=test",
        }
        with self.app.test_request_context("/", headers=headers):
            self.assertFalse(self.plugin.psk_check())
