import http
import unittest
from typing import Optional

import yaml

from turnpike import create_app


class TestConfig(unittest.TestCase):
    """Tests that the provided backends' configuration is correct"""

    def _create_configuration(self, backends_file_path: Optional[str] = None):
        """Utility function to create a basic configuration for Flask."""
        test_config = {
            "AUTH_DEBUG": True,
            "AUTH_PLUGIN_CHAIN": ["turnpike.plugins.x509.X509AuthPlugin", "turnpike.plugins.saml.SAMLAuthPlugin"],
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
        }

        if backends_file_path:
            with open(backends_file_path) as backends_file:
                test_config["BACKENDS"] = yaml.safe_load(backends_file)

        return test_config

    def test_backend_config_empty_backends(self):
        """Tests that when no backends have been given to Flask, an exception is raised."""
        test_config = self._create_configuration()

        with self.assertRaises(NotImplementedError) as context:
            create_app(test_config)

        self.assertTrue("No backends have been configured in the application" in context.exception.__str__())

    def test_backend_config_oidc_missing_service_accounts(self):
        """Tests that when an OIDC back end does not have the 'service accounts' defined, an exception is raised."""
        test_config = self._create_configuration("./tests/backends/invalid-configs/oidc-missing-service-accounts.yaml")

        with self.assertRaises(NotImplementedError) as context:
            create_app(test_config)

        self.assertTrue(
            'The backend "turnpike-general" contains an empty "oidc" object. Either add some service accounts or delete it.'
            in context.exception.__str__()
        )

    def test_backend_config_oidc_empty_service_accounts(self):
        """Tests that when an OIDC back end contains an empty 'service accounts' object, an exception is raised."""
        test_config = self._create_configuration("./tests/backends/invalid-configs/oidc-empty-service-accounts.yaml")

        with self.assertRaises(NotImplementedError) as context:
            create_app(test_config)

        self.assertTrue(
            'The backend "turnpike-general" has a "serviceAccounts" definition but the list is empty'
            in context.exception.__str__()
        )

    def test_backend_config_oidc_missing_client_id(self):
        """Tests that when an OIDC back end contains a 'service accounts' object with a missing client id, an exception is raised."""
        test_config = self._create_configuration("./tests/backends/invalid-configs/oidc-missing-client-id.yaml")

        with self.assertRaises(NotImplementedError) as context:
            create_app(test_config)

        self.assertTrue(
            'The backend "turnpike-general" has a "service account" defined with a missing "clientId" property'
            in context.exception.__str__()
        )

    def test_backend_config_oidc_empty_client_id(self):
        """Tests that when an OIDC back end contains a 'service accounts' object with an empty client id, an exception is raised."""
        test_config = self._create_configuration("./tests/backends/invalid-configs/oidc-empty-client-id.yaml")

        with self.assertRaises(NotImplementedError) as context:
            create_app(test_config)

        self.assertTrue(
            'The backend "turnpike-general" has a "service account" defined with an empty "clientId" property'
            in context.exception.__str__()
        )

    def test_backend_config_oidc_empty_scopes(self):
        """Tests that when an OIDC back end contains a 'service accounts' object with an empty 'scopes' object, an exception is raised."""
        test_config = self._create_configuration("./tests/backends/invalid-configs/oidc-empty-scopes.yaml")

        with self.assertRaises(NotImplementedError) as context:
            create_app(test_config)

        self.assertTrue(
            'The backend "turnpike-general" has a "service account" defined with an empty "scopes" property. Either add some scopes or delete the "scopes" definition.'
            in context.exception.__str__()
        )

    def test_backend_config_oidc_empty_scope_in_list(self):
        """Tests that when an OIDC back end contains a 'service accounts' object with a list of scopes that contains an empty scope, an exception is raised."""
        test_config = self._create_configuration("./tests/backends/invalid-configs/oidc-scopes-empty-element.yaml")

        with self.assertRaises(NotImplementedError) as context:
            create_app(test_config)

        self.assertTrue(
            'The backend "turnpike-general" has a "service account" defined with a list that has an empty scope.'
            in context.exception.__str__()
        )


if __name__ == "__main__":
    unittest.main()
