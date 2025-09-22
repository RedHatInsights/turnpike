import os
import sys
import http
import unittest
import yaml

sys.path.append(os.path.abspath("./tests/mocked_plugins"))
sys.path.append(os.path.abspath("./turnpike"))

from turnpike import create_app
from turnpike.plugins.x509 import X509AuthPlugin


class TestAlternativeGatewaySecret(unittest.TestCase):
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
                "HEADER_CERTAUTH_PSK": "x-rh-insights-gateway-secret",
                "HEADER_CERTAUTH_PSK_ALT": "x-rh-insights-alt-gateway-secret",
                "CDN_PRESHARED_KEY_ALT": "alt-gateway-secret",
                "PLUGIN_CHAIN": [
                    "tests.mocked_plugins.mocked_plugin.MockPlugin",
                ],
                "SECRET_KEY": "alt-gateway-secret",
            }

        self.app = create_app(test_config)
        self.app.config.update({"TESTING": True})
        self.plugin = X509AuthPlugin(self.app)

    def test_accepts_alternative_gateway_secret(self):
        """Alt secret provided under the alternative header should be accepted."""
        headers = {
            # main header must exist (value ignored when alt header supplies the alt secret)
            self.plugin.cdn_psk: "ignored",
            self.plugin.cdn_psk_alt: "alt-gateway-secret",
            self.plugin.subject_header: "CN=test",
        }
        with self.app.test_request_context("/", headers=headers):
            self.assertTrue(self.plugin.psk_check())

    def test_rejects_incorrect_alternative_value(self):
        """Both PSK headers present but neither matches configured secrets -> reject."""
        headers = {
            self.plugin.cdn_psk: "wrong-secret",
            self.plugin.cdn_psk_alt: "wrong-secret",
            self.plugin.subject_header: "CN=test",
        }
        with self.app.test_request_context("/", headers=headers):
            self.assertFalse(self.plugin.psk_check())

    def test_accepts_cdn_preshared_key_when_configured(self):
        """Main pre-shared key when configured should be accepted."""
        self.app.config["CDN_PRESHARED_KEY"] = "shared-secret"
        headers = {
            self.plugin.cdn_psk: "shared-secret",
            # ensure alt header is present to avoid KeyError inside psk_check
            self.plugin.cdn_psk_alt: "",
            self.plugin.subject_header: "CN=test",
        }
        with self.app.test_request_context("/", headers=headers):
            self.assertTrue(self.plugin.psk_check())
