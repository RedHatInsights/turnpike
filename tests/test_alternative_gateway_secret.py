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


def _make_x509_app(**config_overrides):
    with open("./tests/backends/test-backends.yaml") as f:
        test_config = {
            "AUTH_DEBUG": True,
            "AUTH_PLUGIN_CHAIN": ["turnpike.plugins.x509.X509AuthPlugin"],
            "BACKENDS": yaml.safe_load(f),
            "CACHE_TYPE": "SimpleCache",
            "DEFAULT_RESPONSE_CODE": http.HTTPStatus.INTERNAL_SERVER_ERROR,
            "HEADER_CERTAUTH_SUBJECT": "subject",
            "HEADER_CERTAUTH_ISSUER": "issuer",
            "HEADER_CERTAUTH_PSK": "x-rh-insights-gateway-secret",
            "PLUGIN_CHAIN": ["tests.mocked_plugins.mocked_plugin.MockPlugin"],
            "SECRET_KEY": "test-secret",
        }
    test_config.update(config_overrides)
    app = create_app(test_config)
    return app, X509AuthPlugin(app)


class TestX509PSKEdgeCases(unittest.TestCase):
    """Test edge cases for PSK validation, particularly None handling and constant-time comparison."""

    def test_both_keys_none(self):
        """When both CDN_PRESHARED_KEY and CDN_PRESHARED_KEY_ALT are None, psk_check should return False."""
        app, plugin = _make_x509_app()

        headers = {plugin.cdn_psk: "any-value"}
        with app.test_request_context("/", headers=headers):
            self.assertFalse(plugin.psk_check())

    def test_primary_key_none_alt_set(self):
        """When CDN_PRESHARED_KEY is None but CDN_PRESHARED_KEY_ALT is set, only alt key should be checked."""
        app, plugin = _make_x509_app(CDN_PRESHARED_KEY_ALT="alt-secret")

        headers = {plugin.cdn_psk: "alt-secret"}
        with app.test_request_context("/", headers=headers):
            self.assertTrue(plugin.psk_check())

        headers = {plugin.cdn_psk: "wrong-secret"}
        with app.test_request_context("/", headers=headers):
            self.assertFalse(plugin.psk_check())

    def test_alt_key_none_primary_set(self):
        """When CDN_PRESHARED_KEY_ALT is None but CDN_PRESHARED_KEY is set, only primary key should be checked."""
        app, plugin = _make_x509_app(CDN_PRESHARED_KEY="primary-secret")

        headers = {plugin.cdn_psk: "primary-secret"}
        with app.test_request_context("/", headers=headers):
            self.assertTrue(plugin.psk_check())

        headers = {plugin.cdn_psk: "wrong-secret"}
        with app.test_request_context("/", headers=headers):
            self.assertFalse(plugin.psk_check())

    def test_both_keys_set_primary_matches(self):
        """When both keys are set and request matches primary, psk_check should return True."""
        app, plugin = _make_x509_app(CDN_PRESHARED_KEY="primary-secret", CDN_PRESHARED_KEY_ALT="alt-secret")

        headers = {plugin.cdn_psk: "primary-secret"}
        with app.test_request_context("/", headers=headers):
            self.assertTrue(plugin.psk_check())

    def test_both_keys_set_alt_matches(self):
        """When both keys are set and request matches alt, psk_check should return True."""
        app, plugin = _make_x509_app(CDN_PRESHARED_KEY="primary-secret", CDN_PRESHARED_KEY_ALT="alt-secret")

        headers = {plugin.cdn_psk: "alt-secret"}
        with app.test_request_context("/", headers=headers):
            self.assertTrue(plugin.psk_check())

    def test_both_keys_set_neither_matches(self):
        """When both keys are set and request matches neither, psk_check should return False."""
        app, plugin = _make_x509_app(CDN_PRESHARED_KEY="primary-secret", CDN_PRESHARED_KEY_ALT="alt-secret")

        headers = {plugin.cdn_psk: "wrong-secret"}
        with app.test_request_context("/", headers=headers):
            self.assertFalse(plugin.psk_check())

    def test_empty_string_request_secret(self):
        """When request_secret is empty string, psk_check should return False."""
        app, plugin = _make_x509_app(CDN_PRESHARED_KEY="valid-secret")

        headers = {plugin.cdn_psk: ""}
        with app.test_request_context("/", headers=headers):
            self.assertFalse(plugin.psk_check())
