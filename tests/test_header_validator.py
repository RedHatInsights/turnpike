import http
import uuid
from unittest import TestCase
from unittest.mock import Mock

from turnpike import create_app
from turnpike.plugins.common.header_validator import HeaderValidator
from turnpike.plugins.common.invalid_header_error import InvalidHeaderError


class TestHeaderValidator(TestCase):
    """Tests for the "HeaderValidator" class."""

    def set_up_header_validator(self, environment: str) -> HeaderValidator:
        """Set up a "header validator" with the given environment."""
        app_mock = Mock
        app_mock.config = {"WEB_ENV", environment}
        test_config = {
            "APP_NAME": uuid.uuid4().__str__(),
            "AUTH_DEBUG": True,
            "AUTH_PLUGIN_CHAIN": ["turnpike.plugins.x509.X509AuthPlugin", "turnpike.plugins.saml.SAMLAuthPlugin"],
            "BACKENDS": [{"name": "header-validator-tests", "origin": "https://localhost.local", "auth": {}}],
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
        return HeaderValidator(app)

    def test_is_edge_host_header_vpn(self):
        """Tests that the function under test correctly identifies VPN "edge host" headers."""
        header_validator = self.set_up_header_validator("stage")

        edge_host_vpn_headers: list[str] = [
            "mtls.private.console.stage.redhat.com",
            "mtls.private.console.dev.redhat.com",
            "mtls.private.cloud.stage.redhat.com",
            "mtls.private.cloud.dev.redhat.com",
            "private.console.stage.redhat.com",
            "private.console.dev.redhat.com",
            "private.cloud.stage.redhat.com",
            "private.cloud.dev.redhat.com",
        ]

        for header in edge_host_vpn_headers:
            self.assertTrue(
                header_validator.is_edge_host_header_vpn(header), f'header value "{header}" not identified as VPN host'
            )

    def test_is_not_edge_host_header_vpn(self):
        """Tests that the function under test correctly identifies non VPN hosts in the "edge host" header."""
        header_validator = self.set_up_header_validator("stage")

        edge_host_vpn_headers: list[str] = [
            "mtls.internal.console.stage.redhat.com",
            "mtls.internal.console.dev.redhat.com",
            "mtls.internal.cloud.stage.redhat.com",
            "mtls.internal.cloud.dev.redhat.com",
            "internal.console.stage.redhat.com",
            "internal.console.dev.redhat.com",
            "internal.cloud.stage.redhat.com",
            "internal.cloud.dev.redhat.com",
        ]

        for header in edge_host_vpn_headers:
            self.assertFalse(
                header_validator.is_edge_host_header_vpn(header), f'header value "{header}" identified as VPN host'
            )

    def test_unrecognized_edge_host(self):
        """Tests that the function under test raises an error for an unrecognized "edge host"."""
        header_validator = self.set_up_header_validator("stage")

        with self.assertRaises(InvalidHeaderError) as cm:
            header_validator.validate_edge_host_header_vpn("redhat.com")

        self.assertEqual(
            f'[{header_validator.EDGE_HOST_HEADER}: "redhat.com"] Unrecognized edge host', str(cm.exception)
        )

    def test_non_prod_host_in_production(self):
        """Tests that the function under test raises an error for a non-prod "edge host" while in a production environment."""
        header_validator = self.set_up_header_validator("production")

        with self.assertRaises(InvalidHeaderError) as cm:
            header_validator.validate_edge_host_header_vpn("mtls.internal.console.stage.redhat.com")

        self.assertEqual(
            f'[{header_validator.EDGE_HOST_HEADER}: "mtls.internal.console.stage.redhat.com"] Request comes from a non-production environment',
            str(cm.exception),
        )

    def test_prod_host_in_non_prod(self):
        """Tests that the function under test raises an error for a prod "edge host" while in a non-production environment."""
        header_validator = self.set_up_header_validator("stage")

        with self.assertRaises(InvalidHeaderError) as cm:
            header_validator.validate_edge_host_header_vpn("mtls.internal.console.redhat.com")

        self.assertEqual(
            f'[{header_validator.EDGE_HOST_HEADER}: "mtls.internal.console.redhat.com"] Request comes from a production environment',
            str(cm.exception),
        )

    def test_valid_header(self):
        """Tests that the function under test does not raise an error when a valid "edge host" value is passed."""
        non_prod_header_validator = self.set_up_header_validator("stage")
        non_prod_header_validator.validate_edge_host_header_vpn("internal.console.stage.redhat.com")

        prod_header_validator = self.set_up_header_validator("prod")
        prod_header_validator.validate_edge_host_header_vpn("internal.console.redhat.com")
