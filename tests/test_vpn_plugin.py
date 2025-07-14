import http
import uuid
from unittest import TestCase, mock

from turnpike import create_app
from turnpike.plugin import PolicyContext
from turnpike.plugins.vpn import VPNPlugin


class TestVPNPlugin(TestCase):
    def setUpVPNPlugin(self, backend: dict, environment: str) -> VPNPlugin:
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

    def test_edge_host_missing(self):
        """Test that a request without an "edge host" header that comes for a back end without a "private:true" directive skips the VPN plug in."""
        context = PolicyContext()
        context.backend = {
            "name": "vpn-test",
        }
        request = mock.Mock
        request.headers = {}
        vpn_plugin = self.setUpVPNPlugin(backend=context.backend, environment="stage")

        with mock.patch("turnpike.plugins.vpn.request", request):
            # Call the plugin under test.
            vpn_plugin.process(context=context)

            # Ensure that no status code has been set.
            self.assertIsNone(context.status_code)

    def test_edge_host_missing_backend_private(self):
        """Test that a back end with a "private: true" directive requires all requests to come from the VPN."""
        context = PolicyContext()
        context.backend = {
            "name": "vpn-test",
            "private": True,
        }
        request = mock.Mock
        request.headers = {}
        vpn_plugin = self.setUpVPNPlugin(backend=context.backend, environment="stage")

        with (
            self.assertLogs(vpn_plugin.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.vpn.request", request),
        ):
            # Call the plugin under test.
            vpn_plugin.process(context=context)

            # Ensure that the request is denied with a "Forbidden" status code.
            self.assertEqual(http.HTTPStatus.FORBIDDEN, context.status_code)

            # Ensure that the correct log message has been issued.
            self.assertIn(
                f'INFO:{vpn_plugin.app.name}:request to backend \'{context.backend["name"]}\' denied - missing \'x-rh-edge-host\' header which is required for vpn restricted backend',
                cm.output[0],
            )

    def test_edge_host_header_no_matches(self):
        """Test that non-matching "edge host" headers deny the request."""
        context = PolicyContext()
        context.backend = {
            "name": "vpn-test",
            "private": True,
        }
        request = mock.Mock
        request.headers = {}
        vpn_plugin = self.setUpVPNPlugin(backend=context.backend, environment="stage")

        for edge_host_header in [
            "redhat.com",
            "private.redhat.com",
            "internal.redhat.com",
        ]:
            request.headers[vpn_plugin.edge_host_header] = edge_host_header
            with (
                self.assertLogs(vpn_plugin.app.logger.name, level="DEBUG") as cm,
                mock.patch("turnpike.plugins.vpn.request", request),
            ):
                # Call the plugin under test.
                vpn_plugin.process(context=context)

                # Ensure that the request is denied with a "Forbidden" status code.
                self.assertEqual(http.HTTPStatus.FORBIDDEN, context.status_code)

                # Ensure that the correct log message has been issued.
                self.assertIn(
                    f'INFO:{vpn_plugin.app.name}:request to backend \'{context.backend["name"]}\' denied - \'{vpn_plugin.edge_host_header}\':\'{edge_host_header}\' does not originate from vpn restricted edge host',
                    cm.output[0],
                )

    def test_edge_host_header_production_stage_match(self):
        """Test that when the application is production mode and the edge host comes from stage, the request is rejected."""
        context = PolicyContext()
        context.backend = {
            "name": "vpn-test",
            "private": True,
        }
        request = mock.Mock
        request.headers = {}
        vpn_plugin = self.setUpVPNPlugin(backend=context.backend, environment="prod")

        for edge_host_header in [
            "mtls.private.console.stage.redhat.com",
            "mtls.private.cloud.stage.redhat.com",
            "mtls.private.console.dev.redhat.com",
            "mtls.private.cloud.dev.redhat.com",
            "private.console.stage.redhat.com",
            "private.cloud.stage.redhat.com",
            "private.console.dev.redhat.com",
            "private.cloud.dev.redhat.com",
        ]:
            request.headers[vpn_plugin.edge_host_header] = edge_host_header
            with (
                self.assertLogs(vpn_plugin.app.logger.name, level="DEBUG") as cm,
                mock.patch("turnpike.plugins.vpn.request", request),
            ):
                # Call the plugin under test.
                vpn_plugin.process(context=context)

                # Ensure that the request is denied with a "Forbidden" status code.
                self.assertEqual(http.HTTPStatus.FORBIDDEN, context.status_code)

                # Ensure that the correct log message has been issued.
                self.assertIn(
                    f'INFO:{vpn_plugin.app.name}:request to backend \'{context.backend["name"]}\' denied - \'{vpn_plugin.edge_host_header}\':\'{edge_host_header}\' is from edge host in wrong env, expected prod host',
                    cm.output[0],
                )

    def test_edge_host_header_stage_no_match(self):
        """Test that when the application is in stage or dev mode, and the request comes from production, the request is rejected."""
        context = PolicyContext()
        context.backend = {
            "name": "vpn-test",
            "private": True,
        }
        request = mock.Mock
        request.headers = {}
        vpn_plugin = self.setUpVPNPlugin(backend=context.backend, environment="stage")

        for edge_host_header in [
            "mtls.private.console.redhat.com",
            "mtls.private.cloud.redhat.com",
            "mtls.private.console.redhat.com",
            "mtls.private.cloud.redhat.com",
            "private.console.redhat.com",
            "private.cloud.redhat.com",
            "private.console.redhat.com",
            "private.cloud.redhat.com",
        ]:
            request.headers[vpn_plugin.edge_host_header] = edge_host_header
            with (
                self.assertLogs(vpn_plugin.app.logger.name, level="DEBUG") as cm,
                mock.patch("turnpike.plugins.vpn.request", request),
            ):
                # Call the plugin under test.
                vpn_plugin.process(context=context)

                # Ensure that the request is denied with a "Forbidden" status code.
                self.assertEqual(http.HTTPStatus.FORBIDDEN, context.status_code)

                # Ensure that the correct log message has been issued.
                self.assertIn(
                    f'INFO:{vpn_plugin.app.name}:request to backend \'{context.backend["name"]}\' denied - \'{vpn_plugin.edge_host_header}\':\'{edge_host_header}\' is from edge host in wrong env, expected non prod host',
                    cm.output[0],
                )

    def test_edge_host_header_valid_sets_nginx_header_flag(self):
        """Test that when the edge host is valid, the header flag that tells Nginx that the request comes from the VPN is set in the context."""
        context = PolicyContext()
        context.backend = {
            "name": "vpn-test",
            "private": True,
        }
        request = mock.Mock
        request.headers = {}
        vpn_plugin = self.setUpVPNPlugin(backend=context.backend, environment="stage")

        request.headers[vpn_plugin.edge_host_header] = "mtls.private.console.stage.redhat.com"
        with (
            self.assertLogs(vpn_plugin.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.vpn.request", request),
        ):
            # Call the plugin under test.
            vpn_plugin.process(context=context)

            # Ensure that the header flag for Nginx is set.
            self.assertTrue(context.headers.get(vpn_plugin.nginx_original_request_comes_from_vpn))

            # Ensure that the correct log message has been issued.
            self.assertIn(
                f'DEBUG:{vpn_plugin.app.name}:request to backend \'{context.backend["name"]}\' approved - \'{vpn_plugin.edge_host_header}\':\'{request.headers[vpn_plugin.edge_host_header]}\' is valid for vpn restricted backend',
                cm.output[0],
            )
