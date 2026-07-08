import http
import logging
import os
import unittest
from unittest import mock

import yaml

from turnpike import create_app


class TestLoggingConfig(unittest.TestCase):
    """Tests that the logging configuration respects the LOG_LEVEL and WEB_ENV settings."""

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

    def test_default_log_level_is_debug(self):
        """Without LOG_LEVEL or WEB_ENV, defaults to DEBUG (matching config.py's WEB_ENV default of 'dev')."""
        config = self._create_configuration()
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.DEBUG)

    def test_explicit_log_level_override(self):
        """LOG_LEVEL in config takes precedence over WEB_ENV."""
        config = self._create_configuration(LOG_LEVEL="WARNING", WEB_ENV="prod")
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.WARNING)

    def test_dev_env_uses_debug(self):
        """WEB_ENV=dev sets the log level to DEBUG."""
        config = self._create_configuration(WEB_ENV="dev")
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.DEBUG)

    def test_prod_env_uses_info(self):
        """WEB_ENV=prod sets the log level to INFO."""
        config = self._create_configuration(WEB_ENV="prod")
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.INFO)

    def test_stage_env_uses_info(self):
        """WEB_ENV=stage also uses INFO (only dev gets DEBUG)."""
        config = self._create_configuration(WEB_ENV="stage")
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.INFO)

    def test_invalid_log_level_falls_back(self):
        """An invalid LOG_LEVEL string falls back to the WEB_ENV-based default."""
        config = self._create_configuration(LOG_LEVEL="INVALID", WEB_ENV="dev")
        with self.assertWarns(UserWarning):
            app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.DEBUG)

    def test_log_level_from_env_var(self):
        """LOG_LEVEL env var works when not set in config dict."""
        os.environ["LOG_LEVEL"] = "WARNING"
        config = self._create_configuration()
        app = create_app(config)
        self.assertEqual(app.logger.getEffectiveLevel(), logging.WARNING)


if __name__ == "__main__":
    unittest.main()
