import logging
from flask import request
from jwt import decode, PyJWTError, PyJWKClient
from jwt.exceptions import InvalidTokenError

from ..plugin import TurnpikeAuthPlugin


class JWTODICAuthPlugin(TurnpikeAuthPlugin):
    """
    JWTOIDCAuthPlugin performs authorization on headers that represent a JWT issued by OIDC
    """

    name = "JWT_OIDC"
    principal_type = "JWT"

    authorization_header = "Authorization"
    headers_needed = [authorization_header]

    def __init__(self, app):
        super().__init__(app)
        self.app.logger.info(f"JWT supported algorithms: {self.app.config['JWT_OIDC_SUPPORTED_ALGORITHMS']}")
        self.app.logger.info(f"JWT JWKS URI: {self.app.config['JWT_OIDC_JWKS_URI']}")
        self.app.logger.info(f"JWT Audience: {self.app.config['JWT_OIDC_AUDIENCE']}")
        self.jwks_client = PyJWKClient(self.app.config["JWT_OIDC_JWKS_URI"])
        self.supported_algorithms = self.app.config["JWT_OIDC_SUPPORTED_ALGORITHMS"]
        self.audience = self.app.config['JWT_OIDC_AUDIENCE']

    def process(self, context, backend_auth):
        self.app.logger.debug("Begin JWT_OIDC plugin processing")
        if self.app.config["AUTH_DEBUG"]:
            self.app.logger.debug(
                "JWT_OIDC headers found: "
                f"authorization={request.headers.get(self.authorization_header)} "
            )
        if "jwt" in backend_auth and self.authorization_header in request.headers:
            bearer_text = None
            token = None

            try:
                [bearer_text, token] = request.headers[self.authorization_header].split(' ', 2)
            except ValueError as ve:
                self.app.logger.debug(f"JWT InvalidTokenError: {ve}")

            if bearer_text and bearer_text.lower() == 'bearer' and token:
                authorized = False
                try:
                    signing_key = self.jwks_client.get_signing_key_from_jwt(token)
                    verified_jwt = decode(token, signing_key.key, self.supported_algorithms, audience=self.audience)
                    self.app.logger.debug(f"JWT verified jwt content: {verified_jwt}")
                    context.auth = dict(auth_data=verified_jwt, auth_plugin=self)
                    authorized = True
                except InvalidTokenError as ite:
                    self.app.logger.debug(f"JWT InvalidTokenError: {token}", ite)
                except PyJWTError as jwt_error:
                    self.app.logger.debug(f"JWT PyJWTError: {token}", jwt_error)

                if not authorized:
                    context.status_code = 403
        return context
