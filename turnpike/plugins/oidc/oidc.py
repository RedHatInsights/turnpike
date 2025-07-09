import http
import typing
from typing import Optional

import requests
from flask import request
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import Token, JWTClaimsRegistry
from requests import Response

import turnpike
from turnpike.model.backend import Backend
from turnpike.model.oidc_authentication import OIDCServiceAccountAuthentication
from turnpike.plugin import TurnpikeAuthPlugin, PolicyContext
from turnpike.plugins.oidc.unable_create_keyset_error import UnableCreateKeysetError


class OIDCAuthPlugin(TurnpikeAuthPlugin):
    """A plugin that gives support for JWT-based authentications"""

    # Used in the produced "x-rh-identity" header.
    name = "oidc-service-account"
    principal_type = "Service_Account"

    headers_needed = set("Authorization")

    def __init__(self, app):
        super().__init__(app)

        self.app = app

        sso_oidc_host = app.config["SSO_OIDC_HOST"]
        sso_oidc_port = app.config["SSO_OIDC_PORT"]
        sso_oidc_realm = app.config["SSO_OIDC_REALM"]
        sso_oidc_scheme = app.config["SSO_OIDC_PROTOCOL_SCHEME"]

        # The host contains the URL including the port...
        self.host = f"{sso_oidc_scheme}://{sso_oidc_host}:{sso_oidc_port}/auth/realms/{sso_oidc_realm}"
        # ... but the issuer does not. We need to make this distinction so that when validating the token, the issuer
        # correctly matches.
        self.issuer = f"{sso_oidc_scheme}://{sso_oidc_host}/auth/realms/{sso_oidc_realm}"
        self.oidc_configuration_url = f"{self.host}/.well-known/openid-configuration"

    def _get_jwks_keyset(self) -> KeySet:
        """Generates a key set with which tokens can be verified."""
        jwks_certificates = turnpike.cache.get("oidc_jwks_response")
        if not jwks_certificates:
            try:
                oidc_response: Response = requests.get(url=self.oidc_configuration_url)
            except Exception as e:
                raise UnableCreateKeysetError(f"Unable to fetch the OIDC configuration to validate the token: {e}")

            if not oidc_response.ok:
                raise UnableCreateKeysetError(
                    f"Unexpected status code received when fetching the OIDC configuration: {oidc_response.status_code}. Response body: {oidc_response.content.decode()}"
                )

            self.app.logger.debug('OIDC configuration fetched from "%s"', self.oidc_configuration_url)

            try:
                jwks_uri = oidc_response.json()["jwks_uri"]
            except KeyError:
                raise UnableCreateKeysetError(
                    f"Unable to decode the JWKs' URI from the OIDC response: {oidc_response.content.decode()}"
                )

            try:
                jwks_certificates_response: Response = requests.get(url=jwks_uri)
            except Exception as e:
                raise UnableCreateKeysetError(f"Unable to fetch the JWKS certificates from OIDC: {e}")

            if not jwks_certificates_response.ok:
                raise UnableCreateKeysetError(
                    f"Unexpected status code received when fetching JWKS certificates: {oidc_response.status_code}. Response body: {oidc_response.content.decode()}"
                )

            jwks_certificates = jwks_certificates_response.json()

            # Store the retrieved certificates for 24 hours, which is the recommended caching setting for the JWKS
            # certificates.
            turnpike.cache.set(key="oidc_jwks_response", value=jwks_certificates, timeout=86400)

        try:
            return KeySet.import_key_set(jwks_certificates)
        except Exception as e:
            raise UnableCreateKeysetError(f"Unable to create a keyset from the JWKS certificates: {e}")

    def process(self, context: PolicyContext, backend: Backend) -> PolicyContext:
        # When the given backend does not have an "oidc" section defined, we simply "skip" this plugin by returning
        # the unmodified context.
        if not backend.authentication_oidc:
            self.app.logger.debug(
                'The back end does not have an "oidc" authorization key defined. Skipping "oidc" authorization plugin'
            )

            return context

        # Check that the "Authorization" header was sent.
        bearer_token: Optional[str] = request.headers.get("Authorization")
        if not bearer_token:
            self.app.logger.debug(
                'Skipping OIDC authorization because the request did not have the "Authorization" header'
            )

            return context

        # Skip any requests with a non-"Bearer" authentication scheme, since
        # this plugin only supports that specific one.
        #
        # The capital "B" and the space are an intended thing design make sure
        # the "Authorization" header conforms to the RFC 6750 § 2.1.
        if not bearer_token.startswith("Bearer "):
            self.app.logger.debug(
                f'Skipping the OIDC authorization because the "Authorization" header does not have a "Bearer" authorization scheme or it is malformed'
            )

            return context

        # Get the key set which we will use to verify the signature of the certificate.
        try:
            key_set: KeySet = self._get_jwks_keyset()
        except UnableCreateKeysetError as e:
            self.app.logger.error(f"Unable to generate the keyset to verify the incoming token: {e}")

            context.status_code = http.HTTPStatus.INTERNAL_SERVER_ERROR
            return context

        # Attempt decoding the token with the specified key set. In case the token comes signed with a different key
        # set other than the one we are expecting, a decoding error will be raised.
        try:
            token: Token = jwt.decode(value=bearer_token.removeprefix("Bearer "), key=key_set)
        except Exception as e:
            self.app.logger.warning("Unable to decode token: %s", str(e))

            context.status_code = http.HTTPStatus.UNAUTHORIZED
            return context

        token_client_id: Optional[str] = token.claims.get("clientId")
        if not token_client_id:
            self.app.logger.debug(f'The received token does not contain the "clientId" claim')

            context.status_code = http.HTTPStatus.UNAUTHORIZED
            return context

        # Check whether the client ID from the token is defined in our OIDC configurations.
        target_sa: Optional[OIDCServiceAccountAuthentication.ServiceAccount] = (
            backend.authentication_oidc.service_account_by_client_id(token_client_id)
        )
        if not target_sa:
            self.app.logger.debug(
                f'The client ID "{token_client_id}" from the JWT is not present in the authorized service accounts for the back end'
            )

            context.status_code = http.HTTPStatus.UNAUTHORIZED
            return context

        # Grab the incoming token's scopes.
        token_scope: typing.Optional[str] = token.claims.get("scope")
        token_scopes: list[str]
        if token_scope:
            token_scopes = token_scope.split(" ")
        else:
            token_scopes = []

        # When our configured back end has scopes that need to be validated, make sure that the "scope" claim of the
        # incoming token contains all the scopes that we have defined. The reason why we don't use the
        # "JWTClaimsRegistry" for these checks is that the checks that the registry performs for the "values" argument
        # are not exhaustive, so as long as one of the scopes is present, the validation passes.
        if target_sa.scopes:
            for expected_scope in target_sa.scopes:
                if expected_scope not in token_scopes:
                    self.app.logger.debug(
                        f'The request is denied because the expected scope "{expected_scope}" was not found in the incoming token\'s scopes "{token_scopes}" with client id "{token_client_id}'
                    )

                    context.status_code = http.HTTPStatus.UNAUTHORIZED
                    return context

        try:
            claim_requests = JWTClaimsRegistry(
                exp={"essential": True},
                iss={"essential": True, "value": self.issuer},
            )
            claim_requests.validate(token.claims)
        except Exception as e:
            self.app.logger.debug(f'The claims for the token with client ID "{token_client_id}" are invalid: {e}')

            context.status_code = http.HTTPStatus.UNAUTHORIZED
            return context

        context.auth = dict(
            auth_data={
                "client_id": token_client_id,
                "preferred_username": token.claims.get("preferred_username"),
                "scopes": token_scopes,
            },
            auth_plugin=self,
        )
        return context
