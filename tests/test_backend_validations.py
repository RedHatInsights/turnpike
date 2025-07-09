import os
import sys
import unittest

from turnpike.model.backend import Backend

sys.path.append(os.path.abspath("./nginx"))

from configuration_builder.build_config import InvalidBackendDefinitionError

from configuration_builder import build_config


class TestBackendValidations(unittest.TestCase):

    def test_valid_backends(self):
        """Tests that no errors are raised when the back ends are correctly defined, including those which only are restricted by a "source_ip"."""
        for backend in [
            dict(
                name="valid-test-1",
                route="/api/test",
                origin="http://test-svc.test-namespace.svc.cluster.local:8080/api",
                auth=dict(saml="True"),
            ),
            dict(
                name="valid-test-2",
                route="/public/test",
                origin="http://public-svc.test-namespace.svc.cluster.local/pub",
            ),
            dict(
                name="valid-test-3",
                route="/_test/",
                origin="http://underscore-svc.test-namespace.svc.cluster.local:8000/",
                auth=dict(saml="True"),
            ),
            dict(
                name="valid-test-4",
                route="/public/restricted",
                origin="http://public-restricted.svc.test-namespace.svc.cluster.local:8000/",
                source_ip="10.0.0.0/24",
            ),
        ]:
            try:
                build_config.validate_route(backend)
            except Exception as e:
                self.fail(f"No exceptions were expected to be raised, but the following one was raised instead: {e}")

    def test_invalid_path(self):
        """Tests that back ends with invalid paths raise a validation error."""
        for backend in [
            dict(
                name="no-trailing-slash",
                route="no-starting-slash",
                origin="http://test-svc.test-namespace.svc.cluster.local/foo",
                auth=dict(saml="True"),
            ),
            dict(
                name="not-properly-defined",
                route="/api/test?_=1",
                origin="http://test-svc.test-namespace.svc.cluster.local/bar",
                auth=dict(saml="True"),
            ),
        ]:
            with self.assertRaises(InvalidBackendDefinitionError) as cm:
                build_config.validate_route(backend)

            self.assertEqual(
                f'[backend_name: {backend["name"]}][route: {backend["route"]}] The back end\'s route is not a valid URL path',
                str(cm.exception),
            )

    def test_untrusted_domain(self):
        """Tests that a back end with an untrusted origin domain raises a validation error."""
        backend = dict(
            name="untrusted-domain",
            route="/api/test",
            origin="https://bitcoin-miner.lulz/api/test",
            auth=dict(saml=True),
        )

        with self.assertRaises(InvalidBackendDefinitionError) as cm:
            build_config.validate_route(backend)

        self.assertEqual(
            f'[backend_name: {backend["name"]}][origin: {backend["origin"]}] The back end\'s route\'s origin is in an untrusted domain',
            str(cm.exception),
        )

    def test_protected_route(self):
        """Tests that a back end with a protected route defined raises a validation error."""

        backend = dict(
            name="protected-route",
            route="/auth/suspect",
            origin="http://test-svc.test-namespace.svc.cluster.local:8080/test",
            auth=dict(saml="True"),
        )

        with self.assertRaises(InvalidBackendDefinitionError) as cm:
            build_config.validate_route(backend)

        self.assertEqual(
            f'[backend_name: {backend["name"]}][route: {backend["route"]}] The back end\'s route is a protected route',
            str(cm.exception),
        )

    def test_disallowed_route(self):
        """Tests that a back end with a route which is not allowed raises a validation error."""

        backend = dict(
            name="disallowed-route",
            route="/highly/suspect",
            origin="http://test-svc.test-namespace.svc.cluster.local:8080/test",
            auth=dict(saml="True"),
        )

        with self.assertRaises(InvalidBackendDefinitionError) as cm:
            build_config.validate_route(backend)

        self.assertEqual(
            f'[backend_name: {backend["name"]}][route: {backend["route"]}] The back end\'s route is not part of the allowed routes',
            str(cm.exception),
        )

    def test_restricted_public_routes(self):
        """Tests that a back end which is not restricted by either "auth" or "source_ip" and that does not have the "public" segment in its route raises an exception."""

        backend = dict(
            name="public-unrestricted",
            route="/api/unrestricted",
            origin="http://public-unrestricted-svc.test-namespace.svc.cluster.local:8080/test",
        )

        with self.assertRaises(InvalidBackendDefinitionError) as cm:
            build_config.validate_route(backend)

        self.assertEqual(
            f'[backend_name: {backend["name"]}] The back end does not have either an "auth" or "source_ip" definitions, nor its route\'s first segment begins with the allowed public segments. Either add an access restriction mechanism, or modify the route so that it begins with one of the allowed public segments',
            str(cm.exception),
        )

    def test_backend_config_oidc_empty_service_accounts(self):
        """Tests that when an OIDC back end does not have the 'service accounts' defined, an exception is raised."""
        with self.assertRaises(NotImplementedError) as context:
            Backend(
                {
                    "name": "turnpike-general",
                    "route": "/api/turnpike/v1",
                    "origin": "http://web.svc.cluster.local:12345/api/turnpike/v1",
                    "auth": {"oidc": {"serviceAccounts": {}}},
                }
            )

        self.assertIn(
            'The backend "turnpike-general" has an "oidc" authentication method but the "serviceAccounts" key is either missing or is empty',
            context.exception.__str__(),
        )

    def test_backend_config_oidc_missing_client_id(self):
        """Tests that when an OIDC back end contains a 'service accounts' object with a missing client id, an exception is raised."""
        with self.assertRaises(NotImplementedError) as context:
            Backend(
                {
                    "origin": "http://web.svc.cluster.local:12345/api/turnpike/v1",
                    "route": "/api/turnpike/v1",
                    "name": "turnpike-general",
                    "auth": {
                        "oidc": {
                            "serviceAccounts": [
                                {
                                    "clientId": "b3c001b2-363c-11f0-8477-083a885cd988",
                                    "scopes": ["scope_a", "scope_b", "scope_c"],
                                },
                                {
                                    "clientId": "be2534d3-363c-11f0-b37f-083a885cd988",
                                    "scopes": ["scope_d", "scope_e", "scope_f"],
                                },
                                {"scopes": ["scope_g", "scope_h", "scope_i"]},
                            ]
                        }
                    },
                }
            )

        self.assertIn(
            'The backend "turnpike-general" has a "service account" defined without a properly defined client ID',
            context.exception.__str__(),
        )

    def test_backend_config_oidc_improper_client_id(self):
        """Tests that when an OIDC back end contains a 'service accounts' object with an improperly defined client id, an exception is raised."""
        with self.assertRaises(NotImplementedError) as context:
            Backend(
                {
                    "origin": "http://web.svc.cluster.local:12345/api/turnpike/v1",
                    "route": "/api/turnpike/v1",
                    "name": "turnpike-general",
                    "auth": {
                        "oidc": {
                            "serviceAccounts": [
                                {
                                    "clientId": "b3c001b2-363c-11f0-8477-083a885cd988",
                                    "scopes": ["scope_a", "scope_b", "scope_c"],
                                },
                                {
                                    "clientId": "be2534d3-363c-11f0-b37f-083a885cd988",
                                    "scopes": ["scope_d", "scope_e", "scope_f"],
                                },
                                {"clientId": "", "scopes": ["scope_g", "scope_h", "scope_i"]},
                            ]
                        }
                    },
                }
            )

        self.assertIn(
            'The backend "turnpike-general" has a "service account" defined without a properly defined client ID',
            context.exception.__str__(),
        )

    def test_backend_config_oidc_empty_scopes(self):
        """Tests that when an OIDC back end contains a 'service accounts' object with an empty 'scopes' object, an exception is raised."""
        with self.assertRaises(NotImplementedError) as context:
            Backend(
                {
                    "origin": "http://web.svc.cluster.local:12345/api/turnpike/v1",
                    "route": "/api/turnpike/v1",
                    "name": "turnpike-general",
                    "auth": {
                        "oidc": {
                            "serviceAccounts": [
                                {
                                    "scopes": [
                                        "scope_a",
                                        "scope_b",
                                        "scope_c",
                                    ],
                                    "clientId": "20382883-363d-11f0-9ee4-083a885cd988",
                                },
                                {
                                    "clientId": "20382b03-363d-11f0-9ee5-083a885cd988",
                                },
                                {
                                    "clientId": "20382b44-363d-11f0-9ee6-083a885cd988",
                                    "scopes": [
                                        "scope_d",
                                        "scope_e",
                                        "",
                                    ],
                                },
                            ],
                        },
                    },
                },
            )

        self.assertIn(
            'The backend "turnpike-general" has a "service account" defined with a list that has an empty scope',
            context.exception.__str__(),
        )
