import copy
import http
import uuid
from typing import Optional
from unittest import TestCase, mock

from turnpike import create_app
from turnpike.plugin import PolicyContext
from turnpike.plugins.common.header_validator import HeaderValidator
from turnpike.plugins.vpn import VPNPlugin


class TestVPNPlugin(TestCase):
    default_backend: dict = {
        "name": "test-vpn-plugin",
        "origin": "http://localhost.local",
        "private": True,
    }

    def setUpVPNPlugin(self, environment: str, backend: Optional[dict] = None) -> VPNPlugin:
        if not backend:
            backend = self.default_backend

        test_config = {
            "APP_NAME": uuid.uuid4().__str__(),
            "AUTH_DEBUG": True,
            "AUTH_PLUGIN_CHAIN": ["turnpike.plugins.x509.X509AuthPlugin", "turnpike.plugins.saml.SAMLAuthPlugin"],
            "BACKENDS": [backend],
            "CACHE_TYPE": "SimpleCache",
            "DEFAULT_RESPONSE_CODE": http.HTTPStatus.INTERNAL_SERVER_ERROR,
            "HEADER_CERTAUTH_SUBJECT": "subject",
            "HEADER_CERTAUTH_ISSUER": "issuer",
            "HEADER_CERTAUTH_PSK": "test-psk",
            "SSO_OIDC_HOST": "localhost",
            "SSO_OIDC_PORT": "443",
            "SSO_OIDC_PROTOCOL_SCHEME": "https",
            "SSO_OIDC_REALM": "realm",
            "PLUGIN_CHAIN": [
                "tests.mocked_plugins.mocked_plugin.MockPlugin",
            ],
            "SECRET_KEY": "12345",
            "TESTING": True,
            "WEB_ENV": environment,
        }

        app = create_app(test_config)
        return VPNPlugin(app)

    def test_skip_when_no_backend(self):
        """Test that VPN plugin is skipped when context has no backend."""
        vpn_plugin = self.setUpVPNPlugin("stage")
        context = PolicyContext()
        context.backend = None

        with self.assertLogs(vpn_plugin.app.logger.name, level="INFO") as cm:
            result = vpn_plugin.process(context)

        self.assertIsNone(result.status_code)
        self.assertIn("Skipping VPN plugin because the context does not have a back end", cm.output[0])

    def test_private_backend_invalid_edge_host_header(self):
        """Tests that the plugin sets up a "forbidden" response when the "edge host" header is invalid for a VPN-required back end."""
        vpn_plugin = self.setUpVPNPlugin("stage")
        context = PolicyContext()
        context.backend = self.default_backend

        request_mock = mock.Mock()
        request_mock.headers = {HeaderValidator.EDGE_HOST_HEADER: "mtls.private.console.redhat.com"}

        with (
            self.assertLogs(vpn_plugin.app.logger.name, level="INFO") as cm,
            mock.patch("turnpike.plugins.vpn.request", request_mock),
        ):
            # Call the function under test.
            vpn_plugin.process(context)

            # Assert that a "Forbidden" response is set.
            self.assertEqual(http.HTTPStatus.FORBIDDEN, context.status_code)

            # Ensure that the correct logs were printed.
            self.assertIn(
                f'[backend: "{self.default_backend["name"]}"][{HeaderValidator.EDGE_HOST_HEADER}: "{request_mock.headers[HeaderValidator.EDGE_HOST_HEADER]}"] Request denied. Invalid "edge host" header specified: Request comes from a production environment',
                cm.output[0],
            )

    def test_private_backend_valid_edge_host_header(self):
        """Tests that the plugin does not set any status code in the context when the "edge host" header is correct."""
        vpn_plugin = self.setUpVPNPlugin("production")
        context = PolicyContext()
        context.backend = self.default_backend

        request_mock = mock.Mock()
        request_mock.headers = {HeaderValidator.EDGE_HOST_HEADER: "mtls.private.console.redhat.com"}

        with (
            self.assertLogs(vpn_plugin.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.vpn.request", request_mock),
        ):
            # Call the function under test.
            vpn_plugin.process(context)

            # Ensure that the correct logs were printed.
            self.assertIn(
                f'[backend: "{self.default_backend["name"]}"][{HeaderValidator.EDGE_HOST_HEADER}: "{request_mock.headers[HeaderValidator.EDGE_HOST_HEADER]}"] Request successfully passed through the VPN plugin',
                cm.output[0],
            )

    def test_private_backend_non_private_edge_host_header(self):
        """Tests that the plugin sets up a "forbidden" response when a private back end gets a non-VPN "edge host" header."""
        vpn_plugin = self.setUpVPNPlugin("stage")
        context = PolicyContext()
        context.backend = self.default_backend

        request_mock = mock.Mock()
        request_mock.headers = {HeaderValidator.EDGE_HOST_HEADER: "internal.console.stage.redhat.com"}

        with (
            self.assertLogs(vpn_plugin.app.logger.name, level="INFO") as cm,
            mock.patch("turnpike.plugins.vpn.request", request_mock),
        ):
            # Call the function under test.
            vpn_plugin.process(context)

            # Assert that a "Forbidden" response is set.
            self.assertEqual(http.HTTPStatus.FORBIDDEN, context.status_code)

            # Ensure that the correct logs were printed.
            self.assertIn(
                f'[backend: "{self.default_backend["name"]}"][{HeaderValidator.EDGE_HOST_HEADER}: "{request_mock.headers[HeaderValidator.EDGE_HOST_HEADER]}"] Request denied. Backend requires the requests to come from the VPN',
                cm.output[0],
            )

    def test_public_backend_non_private_edge_host_header(self):
        """Tests that the plugin is skipped when there is a non-private "edge host" header and a public back end."""
        # Make a copy of the default backend and set it as public.
        public_backend = copy.deepcopy(self.default_backend)
        public_backend["private"] = False

        vpn_plugin = self.setUpVPNPlugin(environment="stage", backend=public_backend)
        context = PolicyContext()
        context.backend = public_backend

        request_mock = mock.Mock()
        request_mock.headers = {HeaderValidator.EDGE_HOST_HEADER: "internal.console.stage.redhat.com"}

        with (
            self.assertLogs(vpn_plugin.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.vpn.request", request_mock),
        ):
            # Call the function under test.
            vpn_plugin.process(context)

            # Assert that no status code is set in the context.
            self.assertIsNone(context.status_code)

            # Ensure that the correct logs were printed.
            self.assertIn(
                f'[backend: "{self.default_backend["name"]}"][{HeaderValidator.EDGE_HOST_HEADER}: "{request_mock.headers[HeaderValidator.EDGE_HOST_HEADER]}"] VPN plugin skipped. Backend is not VPN restricted',
                cm.output[0],
            )

    def test_missing_edge_host_header_private_backend(self):
        """Tests that the plugin sets up a "forbidden" response when the request has no "edge host" header but the back end is private."""
        vpn_plugin = self.setUpVPNPlugin("stage")
        context = PolicyContext()
        context.backend = self.default_backend

        request_mock = mock.Mock()
        request_mock.headers = {}

        with (
            self.assertLogs(vpn_plugin.app.logger.name, level="INFO") as cm,
            mock.patch("turnpike.plugins.vpn.request", request_mock),
        ):
            # Call the function under test.
            vpn_plugin.process(context)

            # Assert that a "Forbidden" response is set.
            self.assertEqual(http.HTTPStatus.FORBIDDEN, context.status_code)

            # Ensure that the correct logs were printed.
            self.assertIn(
                f'[backend: "{self.default_backend["name"]}"] Request denied. Missing mandatory "{HeaderValidator.EDGE_HOST_HEADER}" header for VPN restricted backend',
                cm.output[0],
            )

    def test_missing_edge_host_header_public_backend(self):
        """Tests that the plugin is skipped when the request does not have an "edge host" header for a public backend."""
        # Make a copy of the default backend and set it as public.
        public_backend = copy.deepcopy(self.default_backend)
        public_backend["private"] = False

        vpn_plugin = self.setUpVPNPlugin(environment="stage", backend=public_backend)
        context = PolicyContext()
        context.backend = public_backend

        request_mock = mock.Mock()
        request_mock.headers = {}

        with (
            self.assertLogs(vpn_plugin.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.vpn.request", request_mock),
        ):
            # Call the function under test.
            vpn_plugin.process(context)

            # Assert that no status code is set in the context.
            self.assertIsNone(context.status_code)

            # Ensure that the correct logs were printed.
            self.assertIn(
                f'[backend: "{self.default_backend["name"]}"] VPN plugin skipped. Backend is not VPN restricted',
                cm.output[0],
            )
