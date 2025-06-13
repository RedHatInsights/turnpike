import copy
import http
import unittest
import uuid
from datetime import datetime, timedelta
from http import HTTPStatus
from unittest import TestCase, mock

import yaml
from flask import Flask
from requests import Response

from turnpike import create_app
from turnpike.plugins.oidc.oidc import OIDCAuthPlugin


class TestMatchingBackends(TestCase):

    def __init__(self, methodName: str = "runTest"):
        super().__init__(methodName)

    def setUp(self):
        """Set up a mocked Turnpike app."""
        with open("./tests/backends/test-backends.yaml") as test_backends_file:
            test_config = {
                "APP_NAME": uuid.uuid4().__str__(),
                "AUTH_DEBUG": True,
                "AUTH_PLUGIN_CHAIN": ["turnpike.plugins.x509.X509AuthPlugin", "turnpike.plugins.saml.SAMLAuthPlugin"],
                "BACKENDS": yaml.safe_load(test_backends_file),
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

        self.app = create_app(test_config)

        # Create an instance of the plugin under test.
        self.oidc_jwt_plugin = OIDCAuthPlugin(self.app)

        # Build the JWKS URL that we are expecting to see in the assertions.
        self.oidc_configuration_jwks_url = f"{self.oidc_jwt_plugin.issuer}/protocol/openid-connect/certs"

    def _find_jwt_backend(self):
        """Finds the backend that we are using for the tests."""
        for backend in self.app.config["BACKENDS"]:
            if backend["name"] == "notifications-general":
                return backend

        raise Exception("unable to find the mocked backend")

    def _requests_get_side_effect_success(self, url: str) -> mock.Mock:
        """Returns a successful mocked response."""
        if url == self.oidc_jwt_plugin.oidc_configuration_url:
            return mock.Mock(
                status_code=HTTPStatus.OK,
                json=lambda: {"jwks_uri": self.oidc_configuration_jwks_url},
            )
        else:
            return mock.Mock(
                status_code=HTTPStatus.OK,
                json=lambda: {"certificate": "random-certificate"},
            )

    def _requests_side_effect_raise_exception(self, _: str) -> Exception:
        """A side effect that raises an exception."""
        raise Exception("Connection error")

    def _requests_side_effect_oidc_unexpected_status_code(self, url: str) -> Response:
        """A side effect that returns a non-ok status code when attempting to fetch the OIDC configuration."""
        if url == self.oidc_jwt_plugin.oidc_configuration_url:
            response = mock.Mock(status_code=HTTPStatus.BAD_REQUEST)

            # Simulate that the received status code is not a 200 one.
            response.ok = False

            return response

        return mock.Mock()

    def _requests_side_effect_missing_jwks_uri(self, url: str) -> Response:
        """A side effect that returns an OK OIDC response but with the 'jwks_uri' field missing."""
        if url == self.oidc_jwt_plugin.oidc_configuration_url:
            return mock.Mock(
                status_code=HTTPStatus.OK,
                json=lambda: {"random_field": "abcde"},
            )

        return mock.Mock()

    def _requests_side_effect_jwks_fetch_error(self, url: str) -> mock.Mock:
        """A side effect that simulates an error when fetching the JWKS certificates."""
        if url == self.oidc_jwt_plugin.oidc_configuration_url:
            return mock.Mock(
                status_code=HTTPStatus.OK,
                json=lambda: {"jwks_uri": "abcde"},
            )
        else:
            raise Exception("Unable to fetch JWKS certificates")

    def _requests_side_effect_jwks_unexpected_status_code(self, url: str) -> mock.Mock:
        """A side effect that simulates an unexpected status code when fetching the JWKS certificates."""
        if url == self.oidc_jwt_plugin.oidc_configuration_url:
            return mock.Mock(
                status_code=HTTPStatus.OK,
                json=lambda: {"jwks_uri": "abcde"},
            )
        else:
            response = mock.Mock(status_code=HTTPStatus.BAD_REQUEST)

            # Simulate that the received status code is not a 200 one.
            response.ok = False

            return response

    def test_missing_oidc_backend_skips_plugin(self):
        """Test that when the specified backend does not have an "oidc" authorization section, the "oidc" plugin is skipped."""
        context = mock.Mock

        # Assert that a log message is produced.
        with self.assertLogs(self.app.logger.name, level="DEBUG") as cm:
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth={})

            # Ensure that the correct log message has been issued.
            self.assertTrue(
                'The back end does not have an "oidc" authorization key defined. Skipping "oidc" authorization plugin'
                in cm.output[0]
            )

            # Ensure that the context contains the default status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_missing_bearer_token(self):
        """Test that when the bearer token is not present, an unauthorized status code is set in the context."""

        # Set up all the required fields for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock

        # Make a request that does not have the expected "Authorization" header.
        request = mock.Mock
        request.headers = {}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue('Unauthorized the request because the "Authorization" header is missing' in cm.output[0])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_bearer_token_improperly_formatted(self):
        """Test that when the bearer token is improperly formatted, an unauthorized status coe is set in the context."""
        # Set up all the required fields for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock

        # Make a request that contains an improper bearer authorization header.
        request = mock.Mock
        request.headers = {"Authorization": "Bearerinvalid"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue(
                'The received "Authorization" header does not contain a properly formatted bearer token'
                in cm.output[0]
            )

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_unable_get_oidc_configuration(self):
        """Tests that when we are unable to get the OIDC configuration, an error is raised and an internal server error is returned."""

        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Simulate that an error is raised when making the HTTP call to fetch the OIDC results.
        get = mock.Mock(side_effect=self._requests_side_effect_raise_exception)

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="ERROR") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.requests.get", get),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue("Unable to fetch the OIDC configuration to validate the token:" in cm.output[0])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.INTERNAL_SERVER_ERROR, context.status_code)

    def test_unable_get_oidc_configuration_unexpected_status_code(self):
        """Tests that when we are unable to get the OIDC configuration, an error is raised and an internal server error is returned."""

        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Simulate that an error is raised when making the HTTP call to fetch the OIDC results.
        get = mock.Mock(side_effect=self._requests_side_effect_oidc_unexpected_status_code)

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="ERROR") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.requests.get", get),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue("Unexpected status code received when fetching the OIDC configuration:" in cm.output[0])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.INTERNAL_SERVER_ERROR, context.status_code)

    def test_non_existing_jwks_uri_key(self):
        """Tests that when the OIDC response does not contain the expected 'jwks_uri' field an error is returned and an internal server error is also returned."""

        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Simulate that an error is raised when making the HTTP call to fetch the OIDC results.
        get = mock.Mock(side_effect=self._requests_side_effect_missing_jwks_uri)

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.requests.get", get),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue("OIDC configuration fetched from" in cm.output[0])
            self.assertTrue("Unable to decode the JWKs' URI from the OIDC response:" in cm.output[1])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.INTERNAL_SERVER_ERROR, context.status_code)

    def test_unable_get_jwks_certificates(self):
        """Tests that when an error occurs when fetching the JWKS certificates, an error is raised and an internal server error is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Simulate that an error is raised when making the HTTP call to fetch the OIDC results.
        get = mock.Mock(side_effect=self._requests_side_effect_jwks_fetch_error)

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.requests.get", get),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue("OIDC configuration fetched from" in cm.output[0])
            self.assertTrue("Unable to fetch the JWKS certificates from OIDC:" in cm.output[1])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.INTERNAL_SERVER_ERROR, context.status_code)

    def test_unable_get_jwks_certificates_unexpected_status_code(self):
        """Tests that when an unexpected status code is returning when fetching the JWKS certificates, an error is returned and an internal server error too."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Simulate that an error is raised when making the HTTP call to fetch the OIDC results.
        get = mock.Mock(side_effect=self._requests_side_effect_jwks_unexpected_status_code)

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.requests.get", get),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue("OIDC configuration fetched from" in cm.output[0])
            self.assertTrue("Unexpected status code received when fetching JWKS certificates:" in cm.output[1])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.INTERNAL_SERVER_ERROR, context.status_code)

    def test_unable_generate_keyset(self):
        """Tests that the keyset cannot be built from the JWKS certificates, an error is returned and an internal server error is returned too."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Simulate that IT is responding correctly. However, the keyset will not be able to be generated because the
        # mocked response does not contain valid JWKS certificates.
        get = mock.Mock(side_effect=self._requests_get_side_effect_success)

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.requests.get", get),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue("OIDC configuration fetched from" in cm.output[0])
            self.assertTrue("Unable to create a keyset from the JWKS certificates:" in cm.output[1])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.INTERNAL_SERVER_ERROR, context.status_code)

    def test_unable_decode_token(self):
        """Tests that when decoding the token raises an error, an unauthorized error is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock
        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="WARNING") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue("Unable to decode token:" in cm.output[0])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_token_missing_client_id(self):
        """Tests that when the token is missing the 'client_id' property, an unauthorized response is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        token.claims = {}

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue('The received token does not contain the "clientId" claim' in cm.output[0])

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_token_unauthorized_client_id(self):
        """Tests that when the token's 'client_id' property is not present in our back ends, an unauthorized response is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        token.claims = {"clientId": "ca31f4cd-3613-11f0-8b6e-083a885cd988"}

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue(
                f'The client ID "{token.claims["clientId"]}" from the JWT is not present in the authorized service accounts for the back end'
                in cm.output[0]
            )

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_token_missing_scopes(self):
        """Tests that when the token's scope claim is missing, an unauthorized response is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        token.claims = {"clientId": "721d25ca-3614-11f0-9fb6-083a885cd988"}

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue(
                f'The request is denied because the expected scope "scope_a" was not found in the incoming token\'s scopes "[]" with client id "{token.claims["clientId"]}'
                in cm.output[0]
            )

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_token_missing_some_scopes(self):
        """Tests that when the token's scope claim is missing or empty, an unauthorized response is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        token.claims = {"clientId": "721d25ca-3614-11f0-9fb6-083a885cd988", "scope": "scope_a"}

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertTrue(
                f'The request is denied because the expected scope "scope_b" was not found in the incoming token\'s scopes "{[token.claims["scope"]]}" with client id "{token.claims["clientId"]}'
                in cm.output[0]
            )

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_token_missing_expiration_claim(self):
        """Tests that when the token's expiration claim is missing, an unauthorized response is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        token.claims = {
            "clientId": "721d25ca-3614-11f0-9fb6-083a885cd988",
            "iss": self.oidc_jwt_plugin.issuer,
            "scope": "scope_a scope_b",
        }

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertEqual(
                f'DEBUG:{self.app.name}:The claims for the token with client ID "{token.claims["clientId"]}" are invalid: missing_claim: Missing claim: \'exp\'',
                cm.output[0],
            )

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_token_invalid_expiration_claim(self):
        """Tests that when the token is expired, an unauthorized response is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        yesterday = datetime.today() - timedelta(days=1)
        token.claims = {
            "clientId": "721d25ca-3614-11f0-9fb6-083a885cd988",
            "exp": yesterday.timestamp(),
            "iss": self.oidc_jwt_plugin.issuer,
            "scope": "scope_a scope_b",
        }

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertEqual(
                f'DEBUG:{self.app.name}:The claims for the token with client ID "{token.claims["clientId"]}" are invalid: expired_token: The token is expired',
                cm.output[0],
            )

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_token_missing_issuer_claim(self):
        """Tests that when the token's issuer claim is missing, an unauthorized response is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        tomorrow = datetime.today() + timedelta(days=1)
        token.claims = {
            "clientId": "721d25ca-3614-11f0-9fb6-083a885cd988",
            "exp": tomorrow.timestamp(),
            "scope": "scope_a scope_b",
        }

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertEqual(
                f'DEBUG:{self.app.name}:The claims for the token with client ID "{token.claims["clientId"]}" are invalid: missing_claim: Missing claim: \'iss\'',
                cm.output[0],
            )

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_token_invalid_issuer_claim(self):
        """Tests that when the token's issuer claim is incorrect, an unauthorized response is returned."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        tomorrow = datetime.today() + timedelta(days=1)
        token.claims = {
            "clientId": "721d25ca-3614-11f0-9fb6-083a885cd988",
            "exp": tomorrow.timestamp(),
            "iss": "made-up-issuer",
            "scope": "scope_a scope_b",
        }

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            self.assertLogs(self.app.logger.name, level="DEBUG") as cm,
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the correct log message has been issued.
            self.assertEqual(
                f'DEBUG:{self.app.name}:The claims for the token with client ID "{token.claims["clientId"]}" are invalid: invalid_claim: Invalid claim: \'iss\'',
                cm.output[0],
            )

            # Ensure that the context contains the expected status code.
            self.assertEqual(http.HTTPStatus.UNAUTHORIZED, context.status_code)

    def test_authorized_token_no_scopes_backend(self):
        """Tests that when the back end does not have specific scopes listed, a valid token with any scopes will be authorized."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        tomorrow = datetime.today() + timedelta(days=1)
        token.claims = {
            "clientId": "349675ae-3625-11f0-a5d0-083a885cd988",
            "exp": tomorrow.timestamp(),
            "iss": self.oidc_jwt_plugin.issuer,
            "preferred_username": "my-service-account",
            "scope": "scope_a scope_b scope_c scope_d scope_e",
        }

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the context contains the authorization data.
            if not context.auth:
                self.fail('the context should contain the "auth" field when a token is properly authorized')

            auth_data = context.auth.get("auth_data")
            if not auth_data:
                self.fail('the context should contain the "auth_data" field when a token is properly authorized')

            self.assertEqual(
                token.claims["clientId"],
                auth_data["client_id"],
                "the client's ID should be part of the authentication data",
            )

            self.assertEqual(
                token.claims["preferred_username"],
                auth_data["preferred_username"],
                "the preferred username should be part of the resulting authentication data",
            )

            self.assertEqual(
                token.claims["scope"].split(" "),
                auth_data["scopes"],
                "the scopes should be part of the resulting authentication data",
            )

    def test_authorized_token_no_scopes_backend_token(self):
        """Tests that when the back end does not have specific scopes listed, a valid token without the 'scope' field also gets authorized."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        tomorrow = datetime.today() + timedelta(days=1)
        token.claims = {
            "clientId": "349675ae-3625-11f0-a5d0-083a885cd988",
            "exp": tomorrow.timestamp(),
            "iss": self.oidc_jwt_plugin.issuer,
            "preferred_username": "my-service-account",
        }

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the context contains the authorization data.
            if not context.auth:
                self.fail('the context should contain the "auth" field when a token is properly authorized')

            auth_data = context.auth.get("auth_data")
            if not auth_data:
                self.fail('the context should contain the "auth_data" field when a token is properly authorized')

            self.assertEqual(
                token.claims["clientId"],
                auth_data["client_id"],
                "the client's ID should be part of the authentication data",
            )

            self.assertEqual(
                token.claims["preferred_username"],
                auth_data["preferred_username"],
                "the preferred username should be part of the resulting authentication data",
            )

            self.assertEqual(
                auth_data["scopes"],
                [],
                "the scopes should be part of the resulting authentication data",
            )

    def test_authorized_token_more_scopes_necessary(self):
        """Tests that when the back end lists certain scopes, and the token has more than the ones listed, the request is authorized."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock
        get_jwks_keyset = mock.Mock

        token = mock.Mock
        tomorrow = datetime.today() + timedelta(days=1)
        token.claims = {
            "clientId": "721d25ca-3614-11f0-9fb6-083a885cd988",
            "exp": tomorrow.timestamp(),
            "iss": self.oidc_jwt_plugin.issuer,
            "preferred_username": "my-service-account",
            "scope": "scope_a scope_b scope_c scope_d scope_e",
        }

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.OIDCAuthPlugin._get_jwks_keyset", get_jwks_keyset),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the context contains the authorization data.
            if not context.auth:
                self.fail('the context should contain the "auth" field when a token is properly authorized')

            auth_data = context.auth.get("auth_data")
            if not auth_data:
                self.fail('the context should contain the "auth_data" field when a token is properly authorized')

            self.assertEqual(
                token.claims["clientId"],
                auth_data["client_id"],
                "the client's ID should be part of the authentication data",
            )

            self.assertEqual(
                token.claims["preferred_username"],
                auth_data["preferred_username"],
                "the preferred username should be part of the resulting authentication data",
            )

            self.assertEqual(
                token.claims["scope"].split(" "),
                auth_data["scopes"],
                "the scopes should be part of the resulting authentication data",
            )

    def test_oidc_requests_get_cached(self):
        """Tests that we only call the IT services once to retrieve the JWKS certificates."""
        # Set up all the required fields and prerequisites for the test.
        backend = self._find_jwt_backend()["auth"]
        context = mock.Mock

        # Simulate that IT is responding correctly. However, the keyset will not be able to be generated because the
        # mocked response does not contain valid JWKS certificates.
        get = mock.Mock(side_effect=self._requests_get_side_effect_success)

        # Mock the function that imports the key set to avoid raising exceptions.
        import_key_set = mock.Mock

        token = mock.Mock
        tomorrow = datetime.today() + timedelta(days=1)
        token.claims = {
            "clientId": "721d25ca-3614-11f0-9fb6-083a885cd988",
            "exp": tomorrow.timestamp(),
            "iss": self.oidc_jwt_plugin.issuer,
            "scope": "scope_a scope_b scope_c scope_d scope_e",
        }

        jwt_decode = mock.Mock
        jwt_decode.return_value = token

        request = mock.Mock
        request.headers = {"Authorization": "Bearer abcde"}

        # Assert that a log message is produced.
        with (
            mock.patch("turnpike.plugins.oidc.oidc.request", request),
            mock.patch("turnpike.plugins.oidc.oidc.requests.get", get),
            mock.patch("turnpike.plugins.oidc.oidc.KeySet.import_key_set", import_key_set),
            mock.patch("turnpike.plugins.oidc.oidc.jwt.decode", jwt_decode),
        ):
            # Call the function under test.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # Ensure that the "requests.get" method gets called twice on the first time, one to fetch the OIDC
            # configuration and another one to fetch the "JWKS" certificates.
            self.assertEqual(2, get.call_count)

            # Call the function under test again.
            self.oidc_jwt_plugin.process(context=context, backend_auth=backend)

            # When the caching is working, the call count should not have been modified because the JWKS certificates
            # should have been picked up from the cache.
            self.assertEqual(2, get.call_count)


if __name__ == "__main__":
    unittest.main()
