import http
import os
import sys
import unittest
import yaml

from turnpike.views.views import policy_view

sys.path.append(os.path.abspath("./tests/mocked_plugins"))
sys.path.append(os.path.abspath("./turnpike"))

from turnpike import create_app
from unittest import mock


class TestMatchingBackends(unittest.TestCase):
    """Tests that the correct back ends are matched by Turnpike depending on what"s provided as an incoming header."""

    def setUp(self):
        """Set up a mocked Turnpike app."""
        with open("./tests/backends/test-backends.yaml") as test_backends_file:
            test_config = {
                "AUTH_DEBUG": True,
                "AUTH_PLUGIN_CHAIN": ["turnpike.plugins.x509.X509AuthPlugin", "turnpike.plugins.saml.SAMLAuthPlugin"],
                "BACKENDS": yaml.safe_load(test_backends_file),
                "CACHE_TYPE": "SimpleCache",
                "DEFAULT_RESPONSE_CODE": http.HTTPStatus.INTERNAL_SERVER_ERROR,
                "HEADER_CERTAUTH_SUBJECT": "subject",
                "HEADER_CERTAUTH_ISSUER": "issuer",
                "HEADER_CERTAUTH_PSK": "test-psk",
                "NGINX_HEADER_BACKEND_MATCHING_ENABLED": True,
                "PLUGIN_CHAIN": [
                    "tests.mocked_plugins.mocked_plugin.MockPlugin",
                ],
                "SECRET_KEY": "12345",
            }

        self.app = create_app(test_config)
        self.app.config.update(
            {
                "TESTING": True,
            }
        )

    def test_unmatched_backends(self):
        """Tests that when a backend is not matched, Turnpike returns a "Forbidden" response."""
        with self.app.app_context():
            mocked_request = mock.Mock
            mocked_request.headers = {"X-Original-Uri": "/", "X-Matched-Backend": "nothing"}

            with mock.patch("turnpike.views.request", mocked_request):
                response = policy_view()

                self.assertEqual(
                    response.status_code,
                    http.HTTPStatus.FORBIDDEN,
                    'when a back end is not matched a "Forbidden" response should be returned to the caller',
                )

    def test_match_by_name(self):
        """Tests that when Nginx sends the back end it matched, Turnpike is able to identify it correctly."""
        with self.app.app_context():
            mocked_request = mock.Mock

            for expected_backend in ["rbac-general", "rbac-health-check"]:
                mocked_request.headers = {"X-Original-Uri": "/", "X-Matched-Backend": expected_backend}

                with mock.patch("turnpike.views.request", mocked_request):
                    # Call the view under test.
                    policy_view()

                    # Attempt grabbing the mocked plugin, to assert that the correct back end was matched.
                    if self.app.config.get("PLUGIN_CHAIN_OBJS")[0]:
                        mocked_plugin = self.app.config.get("PLUGIN_CHAIN_OBJS")[0]
                    else:
                        self.fail("Unable to get the mocked plugin")

                    self.assertEqual(
                        expected_backend,
                        mocked_plugin.matched_backend["name"],
                        "unexpected back end matched by Turnpike",
                    )

    def test_match_by_route(self):
        """Tests that when Nginx does not send the back end that it matched, Turnpike matches it by route instead."""
        with self.app.app_context():
            mocked_request = mock.Mock

            test_cases = [
                {"url": "/api/rbac", "expected_backend": "rbac-general"},
                {"url": "/api/rbac/extra", "expected_backend": "rbac-general"},
                {"url": "/api/rbac/v1/health-check", "expected_backend": "rbac-health-check"},
                {"url": "/api/rbac/v1/health-check/extra", "expected_backend": "rbac-health-check"},
                {"url": "/api/rbac/v2/health-check", "expected_backend": "rbac-general"},
            ]

            for test_case in test_cases:
                mocked_request.headers = {"X-Original-Uri": test_case["url"]}

                with mock.patch("turnpike.views.request", mocked_request):
                    # Call the view under test.
                    policy_view()

                    # Attempt grabbing the mocked plugin, to assert that the correct back end was matched.
                    if self.app.config.get("PLUGIN_CHAIN_OBJS")[0]:
                        mocked_plugin = self.app.config.get("PLUGIN_CHAIN_OBJS")[0]
                    else:
                        self.fail("Unable to get the mocked plugin")

                    self.assertEqual(
                        test_case["expected_backend"],
                        mocked_plugin.matched_backend["name"],
                        "unexpected back end matched by Turnpike",
                    )


if __name__ == "__main__":
    unittest.main()
