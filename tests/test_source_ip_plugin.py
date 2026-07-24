import http
import uuid
from unittest import TestCase, mock

import flask

from turnpike import create_app
from turnpike.plugin import PolicyContext
from turnpike.plugins.source_ip import SourceIPPlugin


class TestSourceIPPlugin(TestCase):
    default_backend: dict = {
        "name": "test-source-ip-plugin",
        "origin": "http://localhost.local",
        "source_ip": ["10.0.0.0/8"],
    }

    def setUpSourceIPPlugin(self, hops_to_edge: int = 0) -> tuple[SourceIPPlugin, flask.Flask]:
        test_config = {
            "APP_NAME": uuid.uuid4().__str__(),
            "AUTH_DEBUG": True,
            "AUTH_PLUGIN_CHAIN": ["turnpike.plugins.x509.X509AuthPlugin", "turnpike.plugins.saml.SAMLAuthPlugin"],
            "BACKENDS": [self.default_backend],
            "CACHE_TYPE": "SimpleCache",
            "DEFAULT_RESPONSE_CODE": http.HTTPStatus.INTERNAL_SERVER_ERROR,
            "HEADER_CERTAUTH_SUBJECT": "subject",
            "HEADER_CERTAUTH_ISSUER": "issuer",
            "HEADER_CERTAUTH_PSK": "test-psk",
            "HOPS_TO_EDGE": hops_to_edge,
            "SSO_OIDC_HOST": "localhost",
            "SSO_OIDC_PORT": "443",
            "SSO_OIDC_PROTOCOL_SCHEME": "https",
            "SSO_OIDC_REALM": "realm",
            "PLUGIN_CHAIN": [
                "tests.mocked_plugins.mocked_plugin.MockPlugin",
            ],
            "SECRET_KEY": "12345",
            "TESTING": True,
            "WEB_ENV": "stage",
        }

        app = create_app(test_config)
        return SourceIPPlugin(app), app

    def test_skip_when_no_source_ip_config(self):
        """Test that SourceIP plugin is skipped when backend has no source_ip config."""
        plugin, app = self.setUpSourceIPPlugin()
        context = PolicyContext()
        context.backend = {"name": "test-no-source-ip", "origin": "http://localhost.local"}

        with app.app_context():
            result = plugin.process(context)

        self.assertIsNone(result.status_code)

    def test_valid_ip_in_allowed_network(self):
        """Test that a valid client IP within an allowed network passes through."""
        plugin, app = self.setUpSourceIPPlugin()
        context = PolicyContext()
        context.backend = self.default_backend

        request_mock = mock.Mock()
        request_mock.headers = {"X-Forwarded-For": "10.1.2.3"}

        with (
            app.app_context(),
            mock.patch("turnpike.plugins.source_ip.request", request_mock),
        ):
            result = plugin.process(context)

        self.assertIsNone(result.status_code)

    def test_ip_not_in_allowed_network(self):
        """Test that a client IP not in any allowed network returns 403."""
        plugin, app = self.setUpSourceIPPlugin()
        context = PolicyContext()
        context.backend = self.default_backend

        request_mock = mock.Mock()
        request_mock.headers = {"X-Forwarded-For": "192.168.1.1"}

        with (
            app.app_context(),
            mock.patch("turnpike.plugins.source_ip.request", request_mock),
        ):
            result = plugin.process(context)

        self.assertEqual(403, result.status_code)

    def test_multiple_allowed_cidr_networks(self):
        """Test matching against multiple allowed CIDR networks."""
        plugin, app = self.setUpSourceIPPlugin()
        context = PolicyContext()
        context.backend = {
            "name": "test-multi-cidr",
            "origin": "http://localhost.local",
            "source_ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        }

        request_mock = mock.Mock()
        request_mock.headers = {"X-Forwarded-For": "172.20.1.1"}

        with (
            app.app_context(),
            mock.patch("turnpike.plugins.source_ip.request", request_mock),
        ):
            result = plugin.process(context)

        self.assertIsNone(result.status_code)

    def test_hops_to_edge_extracts_correct_ip(self):
        """Test that HOPS_TO_EDGE > 0 extracts the correct IP from multi-hop X-Forwarded-For."""
        plugin, app = self.setUpSourceIPPlugin(hops_to_edge=1)
        context = PolicyContext()
        context.backend = self.default_backend

        # With HOPS_TO_EDGE=1, client IP is hops[-2] = "10.1.2.3" (allowed in 10.0.0.0/8)
        request_mock = mock.Mock()
        request_mock.headers = {"X-Forwarded-For": "10.1.2.3, 192.168.1.1"}

        with (
            app.app_context(),
            mock.patch("turnpike.plugins.source_ip.request", request_mock),
        ):
            result = plugin.process(context)

        self.assertIsNone(result.status_code)

    def test_hops_to_edge_denied_when_real_client_not_allowed(self):
        """Test that HOPS_TO_EDGE correctly identifies a disallowed real client IP."""
        plugin, app = self.setUpSourceIPPlugin(hops_to_edge=1)
        context = PolicyContext()
        context.backend = self.default_backend

        # With HOPS_TO_EDGE=1, client IP is hops[-2] = "192.168.1.1" (not in 10.0.0.0/8)
        request_mock = mock.Mock()
        request_mock.headers = {"X-Forwarded-For": "192.168.1.1, 10.1.2.3"}

        with (
            app.app_context(),
            mock.patch("turnpike.plugins.source_ip.request", request_mock),
        ):
            result = plugin.process(context)

        self.assertEqual(403, result.status_code)

    def test_malformed_xff_header(self):
        """Test that a malformed X-Forwarded-For header returns 403."""
        plugin, app = self.setUpSourceIPPlugin()
        context = PolicyContext()
        context.backend = self.default_backend

        request_mock = mock.Mock()
        request_mock.headers = {"X-Forwarded-For": "not-an-ip-address"}

        with (
            app.app_context(),
            mock.patch("turnpike.plugins.source_ip.request", request_mock),
        ):
            result = plugin.process(context)

        self.assertEqual(403, result.status_code)

    def test_ipv6_in_allowed_networks(self):
        """Test IPv6 address matching in allowed networks."""
        plugin, app = self.setUpSourceIPPlugin()
        context = PolicyContext()
        context.backend = {
            "name": "test-ipv6",
            "origin": "http://localhost.local",
            "source_ip": ["2001:db8::/32"],
        }

        request_mock = mock.Mock()
        request_mock.headers = {"X-Forwarded-For": "2001:db8::1"}

        with (
            app.app_context(),
            mock.patch("turnpike.plugins.source_ip.request", request_mock),
        ):
            result = plugin.process(context)

        self.assertIsNone(result.status_code)

    def test_ipv6_not_in_allowed_ipv4_network(self):
        """Test that IPv6 client does not match IPv4-only allowed networks (version filtering)."""
        plugin, app = self.setUpSourceIPPlugin()
        context = PolicyContext()
        context.backend = self.default_backend  # only 10.0.0.0/8 (IPv4)

        request_mock = mock.Mock()
        request_mock.headers = {"X-Forwarded-For": "2001:db8::1"}

        with (
            app.app_context(),
            mock.patch("turnpike.plugins.source_ip.request", request_mock),
        ):
            result = plugin.process(context)

        self.assertEqual(403, result.status_code)
