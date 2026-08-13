import http
import logging
import os
import unittest
from unittest import mock

import yaml

from turnpike import create_app
from turnpike.plugin import PolicyContext


class TestLoggingConfig(unittest.TestCase):
    """Tests that the logging configuration respects the LOG_LEVEL setting."""

    def setUp(self):
        self._env_patcher = mock.patch.dict(os.environ, {}, clear=False)
        self._env_patcher.start()
        os.environ.pop("LOG_LEVEL", None)
        os.environ.pop("WEB_ENV", None)

    def tearDown(self):
        self._env_patcher.stop()

    def _create_configuration(self, **overrides):
        with open("./tests/backends/test-backends.yaml") as f:
            config = {
                "AUTH_DEBUG": True,
                "AUTH_PLUGIN_CHAIN": [
                    "turnpike.plugins.x509.X509AuthPlugin",
                    "turnpike.plugins.saml.SAMLAuthPlugin",
                ],
                "BACKENDS": yaml.safe_load(f),
                "CACHE_TYPE": "SimpleCache",
                "DEFAULT_RESPONSE_CODE": http.HTTPStatus.INTERNAL_SERVER_ERROR,
                "HEADER_CERTAUTH_SUBJECT": "subject",
                "HEADER_CERTAUTH_ISSUER": "issuer",
                "HEADER_CERTAUTH_PSK": "test-psk",
                "PLUGIN_CHAIN": ["tests.mocked_plugins.mocked_plugin.MockPlugin"],
                "SECRET_KEY": "12345",
                "TESTING": True,
            }
            config.update(overrides)
            return config

    def test_default_log_level_is_info(self):
        """Without LOG_LEVEL or WEB_ENV, defaults to INFO (secure-by-default)."""
        config = self._create_configuration()
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.INFO)

    def test_explicit_log_level_override(self):
        """LOG_LEVEL in config is respected."""
        config = self._create_configuration(LOG_LEVEL="WARNING")
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.WARNING)

    def test_explicit_debug_via_log_level(self):
        """LOG_LEVEL=DEBUG enables DEBUG logging when explicitly set."""
        config = self._create_configuration(LOG_LEVEL="DEBUG")
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.DEBUG)

    def test_invalid_log_level_falls_back(self):
        """An invalid LOG_LEVEL string falls back to INFO."""
        config = self._create_configuration(LOG_LEVEL="INVALID")
        with self.assertWarns(UserWarning):
            app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.INFO)

    def test_log_level_from_env_var(self):
        """LOG_LEVEL env var works when not set in config dict."""
        os.environ["LOG_LEVEL"] = "WARNING"
        config = self._create_configuration()
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.WARNING)


class TestAuthDebugGating(unittest.TestCase):
    """Tests that sensitive DEBUG log statements are gated behind AUTH_DEBUG."""

    def _create_configuration(self, **overrides):
        with open("./tests/backends/test-backends.yaml") as f:
            config = {
                "AUTH_DEBUG": False,
                "AUTH_PLUGIN_CHAIN": [
                    "turnpike.plugins.x509.X509AuthPlugin",
                    "turnpike.plugins.saml.SAMLAuthPlugin",
                ],
                "BACKENDS": yaml.safe_load(f),
                "CACHE_TYPE": "SimpleCache",
                "CDN_PRESHARED_KEY": "test-psk-value",
                "DEFAULT_RESPONSE_CODE": http.HTTPStatus.INTERNAL_SERVER_ERROR,
                "HEADER_CERTAUTH_SUBJECT": "x-rh-certauth-cn",
                "HEADER_CERTAUTH_ISSUER": "x-rh-certauth-issuer",
                "HEADER_CERTAUTH_PSK": "x-rh-certauth-psk",
                "LOG_LEVEL": "DEBUG",
                "PLUGIN_CHAIN": ["tests.mocked_plugins.mocked_plugin.MockPlugin"],
                "SECRET_KEY": "12345",
                "TESTING": True,
            }
            config.update(overrides)
            return config

    def _create_app(self, **overrides):
        app = create_app(self._create_configuration(**overrides))
        app.logger.disabled = False
        return app

    def test_rh_identity_suppresses_debug_without_auth_debug(self):
        """RHIdentityPlugin must not log identity header content when AUTH_DEBUG is off."""
        from turnpike.plugins.rh_identity import RHIdentityPlugin

        app = self._create_app(AUTH_DEBUG=False)

        context = PolicyContext()
        context.backend = {"name": "test-backend"}
        context.auth = {
            "auth_data": {"subject_dn": "CN=test"},
            "auth_plugin": type("FakePlugin", (), {"principal_type": "X509", "name": "X509"})(),
        }

        with app.test_request_context("/"):
            plugin = RHIdentityPlugin(app)
            with self.assertLogs(app.logger, level="DEBUG") as cm:
                app.logger.debug("sentinel")
                plugin.process(context)

        messages = " ".join(cm.output)
        self.assertNotIn("Identity header content", messages)

    def test_rh_identity_logs_debug_with_auth_debug(self):
        """RHIdentityPlugin logs identity header content when AUTH_DEBUG is on."""
        from turnpike.plugins.rh_identity import RHIdentityPlugin

        app = self._create_app(AUTH_DEBUG=True)

        context = PolicyContext()
        context.backend = {"name": "test-backend"}
        context.auth = {
            "auth_data": {"subject_dn": "CN=test"},
            "auth_plugin": type("FakePlugin", (), {"principal_type": "X509", "name": "X509"})(),
        }

        with app.test_request_context("/"):
            plugin = RHIdentityPlugin(app)
            with self.assertLogs(app.logger, level="DEBUG") as cm:
                plugin.process(context)

        messages = " ".join(cm.output)
        self.assertIn("Identity header content", messages)

    def test_x509_suppresses_auth_data_without_auth_debug(self):
        """X509AuthPlugin must not log auth_data when AUTH_DEBUG is off."""
        from turnpike.plugins.x509 import X509AuthPlugin

        app = self._create_app(AUTH_DEBUG=False)
        x509_plugin = X509AuthPlugin(app)

        context = PolicyContext()
        context.backend = {
            "name": "test-backend",
            "auth": {"x509": "True"},
        }

        with app.test_request_context(
            "/",
            headers={
                "x-rh-certauth-cn": "CN=test-subject",
                "x-rh-certauth-issuer": "CN=test-issuer",
                "x-rh-certauth-psk": "test-psk-value",
            },
        ):
            with self.assertLogs(app.logger, level="DEBUG") as cm:
                x509_plugin.process(context, context.backend["auth"])

        messages = " ".join(cm.output)
        self.assertNotIn("X509 auth_data", messages)

    def test_x509_logs_auth_data_with_auth_debug(self):
        """X509AuthPlugin logs auth_data when AUTH_DEBUG is on."""
        from turnpike.plugins.x509 import X509AuthPlugin

        app = self._create_app(AUTH_DEBUG=True)
        x509_plugin = X509AuthPlugin(app)

        context = PolicyContext()
        context.backend = {
            "name": "test-backend",
            "auth": {"x509": "True"},
        }

        with app.test_request_context(
            "/",
            headers={
                "x-rh-certauth-cn": "CN=test-subject",
                "x-rh-certauth-issuer": "CN=test-issuer",
                "x-rh-certauth-psk": "test-psk-value",
            },
        ):
            with self.assertLogs(app.logger, level="DEBUG") as cm:
                x509_plugin.process(context, context.backend["auth"])

        messages = " ".join(cm.output)
        self.assertIn("X509 auth_data", messages)

    def test_auth_complete_suppresses_context_without_auth_debug(self):
        """AuthPlugin must not log full context on auth completion when AUTH_DEBUG is off."""
        from turnpike.plugins.auth import AuthPlugin

        app = self._create_app(
            AUTH_DEBUG=False,
            REGISTRY_SERVICE_URL="https://registry.example.com/auth",
            REGISTRY_SERVICE_CLIENT_CERT_PATH="/tmp/test-cert.pem",
            REGISTRY_SERVICE_CLIENT_KEY_PATH="/tmp/test-key.pem",
            REGISTRY_SERVICE_SSL_VERIFY=True,
        )
        auth_plugin = AuthPlugin(app)

        context = PolicyContext()
        context.backend = {
            "name": "test-backend",
            "auth": {"x509": "True"},
        }

        with app.test_request_context(
            "/",
            headers={
                "x-rh-certauth-cn": "CN=test-subject",
                "x-rh-certauth-issuer": "CN=test-issuer",
                "x-rh-certauth-psk": "test-psk-value",
            },
        ):
            with self.assertLogs(app.logger, level="DEBUG") as cm:
                auth_plugin.process(context)

        messages = " ".join(cm.output)
        self.assertNotIn("Auth complete", messages)

    def test_auth_complete_logs_context_with_auth_debug(self):
        """AuthPlugin logs full context on auth completion when AUTH_DEBUG is on."""
        from turnpike.plugins.auth import AuthPlugin

        app = self._create_app(
            AUTH_DEBUG=True,
            REGISTRY_SERVICE_URL="https://registry.example.com/auth",
            REGISTRY_SERVICE_CLIENT_CERT_PATH="/tmp/test-cert.pem",
            REGISTRY_SERVICE_CLIENT_KEY_PATH="/tmp/test-key.pem",
            REGISTRY_SERVICE_SSL_VERIFY=True,
        )
        auth_plugin = AuthPlugin(app)

        context = PolicyContext()
        context.backend = {
            "name": "test-backend",
            "auth": {"x509": "True"},
        }

        with app.test_request_context(
            "/",
            headers={
                "x-rh-certauth-cn": "CN=test-subject",
                "x-rh-certauth-issuer": "CN=test-issuer",
                "x-rh-certauth-psk": "test-psk-value",
            },
        ):
            with self.assertLogs(app.logger, level="DEBUG") as cm:
                auth_plugin.process(context)

        messages = " ".join(cm.output)
        self.assertIn("Auth complete", messages)


if __name__ == "__main__":
    unittest.main()
