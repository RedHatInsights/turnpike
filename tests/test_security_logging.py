import http
import json
import logging
import unittest
from unittest import TestCase

import yaml

from turnpike import create_app
from turnpike.security_logging import log_security_event


def _parse_security_log(log_line):
    """Extract JSON from assertLogs output like 'INFO:turnpike.security:{...}'."""
    prefix = "INFO:turnpike.security:"
    if log_line.startswith(prefix):
        return json.loads(log_line[len(prefix) :])
    raise ValueError(f"Unexpected log format: {log_line}")


class TestSecurityLogging(TestCase):
    """Tests for the centralized security logging module."""

    def setUp(self):
        with open("./tests/backends/test-backends.yaml") as f:
            test_config = {
                "APP_NAME": "test-security-logging",
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
                "SECRET_KEY": "test-secret",
                "TESTING": True,
            }
        self.app = create_app(test_config)

    def test_log_security_event_emits_json(self):
        """log_security_event emits a structured JSON record at INFO level."""
        with self.app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
            with self.assertLogs("turnpike.security", level="INFO") as cm:
                log_security_event("AUTH_DECISION", principal="testuser", status_code=200, backend="my-backend")

        record = _parse_security_log(cm.output[0])
        self.assertEqual(record["event"], "AUTH_DECISION")
        self.assertEqual(record["principal"], "testuser")
        self.assertEqual(record["source_ip"], "10.0.0.1")
        self.assertEqual(record["status_code"], 200)
        self.assertEqual(record["backend"], "my-backend")

    def test_log_security_event_default_principal(self):
        """When principal is not provided, it defaults to 'unknown'."""
        with self.app.test_request_context("/"):
            with self.assertLogs("turnpike.security", level="INFO") as cm:
                log_security_event("AUTH_DECISION", status_code=401)

        record = _parse_security_log(cm.output[0])
        self.assertEqual(record["principal"], "unknown")

    def test_log_security_event_extra_fields(self):
        """Extra keyword arguments are included in the JSON record."""
        with self.app.test_request_context("/"):
            with self.assertLogs("turnpike.security", level="INFO") as cm:
                log_security_event("AUTH_FAILURE", auth_method="x509", reason="predicate_denied")

        record = _parse_security_log(cm.output[0])
        self.assertEqual(record["auth_method"], "x509")
        self.assertEqual(record["reason"], "predicate_denied")

    def test_log_security_event_outside_request_context(self):
        """log_security_event works outside Flask request context (e.g. startup)."""
        with self.assertLogs("turnpike.security", level="INFO") as cm:
            log_security_event("APP_STARTUP")

        record = _parse_security_log(cm.output[0])
        self.assertEqual(record["event"], "APP_STARTUP")
        self.assertEqual(record["source_ip"], "unknown")

    def test_log_security_event_sorted_keys(self):
        """The JSON output has sorted keys for consistent parsing."""
        with self.app.test_request_context("/"):
            with self.assertLogs("turnpike.security", level="INFO") as cm:
                log_security_event("AUTH_DECISION", principal="user1", status_code=200, backend="b1")

        record = _parse_security_log(cm.output[0])
        keys = list(record.keys())
        self.assertEqual(keys, sorted(keys))

    def test_source_ip_from_remote_addr_fallback(self):
        """When X-Forwarded-For is absent, falls back to remote_addr."""
        with self.app.test_request_context("/", environ_base={"REMOTE_ADDR": "192.168.1.1"}):
            with self.assertLogs("turnpike.security", level="INFO") as cm:
                log_security_event("AUTH_DECISION", status_code=200)

        record = _parse_security_log(cm.output[0])
        self.assertEqual(record["source_ip"], "192.168.1.1")


class TestSecurityLoggingInPolicyView(TestCase):
    """Tests that policy_view emits security log events."""

    def setUp(self):
        with open("./tests/backends/test-backends.yaml") as f:
            test_config = {
                "APP_NAME": "test-security-policy-view",
                "AUTH_DEBUG": True,
                "AUTH_PLUGIN_CHAIN": [
                    "turnpike.plugins.x509.X509AuthPlugin",
                    "turnpike.plugins.saml.SAMLAuthPlugin",
                ],
                "BACKENDS": yaml.safe_load(f),
                "CACHE_TYPE": "SimpleCache",
                "DEFAULT_RESPONSE_CODE": http.HTTPStatus.OK,
                "HEADER_CERTAUTH_SUBJECT": "subject",
                "HEADER_CERTAUTH_ISSUER": "issuer",
                "HEADER_CERTAUTH_PSK": "test-psk",
                "PLUGIN_CHAIN": [
                    "turnpike.plugins.auth.AuthPlugin",
                ],
                "SECRET_KEY": "test-secret",
                "TESTING": True,
            }
        self.app = create_app(test_config)
        self.client = self.app.test_client()

    def test_auth_decision_logged_on_401(self):
        """When all auth plugins skip (no credentials), a 401 AUTH_DECISION is logged."""
        with self.assertLogs("turnpike.security", level="INFO") as cm:
            self.client.get("/auth/", headers={"X-Original-Uri": "/api/rbac/something"})

        auth_logs = [line for line in cm.output if "AUTH_DECISION" in line]
        self.assertTrue(len(auth_logs) >= 1, f"Expected AUTH_DECISION log, got: {cm.output}")
        record = _parse_security_log(auth_logs[0])
        self.assertEqual(record["status_code"], 401)
        self.assertEqual(record["backend"], "rbac-general")

    def test_no_auth_backend_no_security_log(self):
        """When no auth is required for a backend, no AUTH_DECISION security log is emitted."""
        with open("./tests/backends/test-backends.yaml") as f:
            backends = yaml.safe_load(f)
        backends.append({"name": "public-api", "route": "/api/public"})

        test_config = {
            "APP_NAME": "test-security-no-auth",
            "AUTH_DEBUG": True,
            "AUTH_PLUGIN_CHAIN": [
                "turnpike.plugins.x509.X509AuthPlugin",
                "turnpike.plugins.saml.SAMLAuthPlugin",
            ],
            "BACKENDS": backends,
            "CACHE_TYPE": "SimpleCache",
            "DEFAULT_RESPONSE_CODE": http.HTTPStatus.OK,
            "HEADER_CERTAUTH_SUBJECT": "subject",
            "HEADER_CERTAUTH_ISSUER": "issuer",
            "HEADER_CERTAUTH_PSK": "test-psk",
            "PLUGIN_CHAIN": ["turnpike.plugins.auth.AuthPlugin"],
            "SECRET_KEY": "test-secret",
            "TESTING": True,
        }
        app = create_app(test_config)
        client = app.test_client()

        with self.assertNoLogs("turnpike.security", level="INFO"):
            client.get("/auth/", headers={"X-Original-Uri": "/api/public/endpoint"})


class TestSecurityLoggingInStartup(TestCase):
    """Tests that app startup emits a security log event."""

    def test_startup_emits_security_log(self):
        """create_app should emit an APP_STARTUP security event."""
        with open("./tests/backends/test-backends.yaml") as f:
            test_config = {
                "APP_NAME": "test-security-startup",
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
                "SECRET_KEY": "test-secret",
                "TESTING": True,
            }

        with self.assertLogs("turnpike.security", level="INFO") as cm:
            create_app(test_config)

        startup_logs = [line for line in cm.output if "APP_STARTUP" in line]
        self.assertTrue(len(startup_logs) >= 1, f"Expected APP_STARTUP log, got: {cm.output}")
        record = _parse_security_log(startup_logs[0])
        self.assertIn("plugin_chain", record)


if __name__ == "__main__":
    unittest.main()
