import base64
from http import HTTPStatus

import requests
from flask import request

from turnpike import cache
from ..plugin import TurnpikeAuthPlugin


class RegistryAuthPlugin(TurnpikeAuthPlugin):
    """
    RegistryAuthPlugin authenticates requests using Basic Auth credentials
    against an external registry service. Credentials are POSTed over mTLS
    and the registry must respond with {"access": {"pull": "granted"}}.

    The Basic Auth username is expected in "org_id|username" format.
    """

    name = "registry-auth"
    principal_type = "Registry"
    headers_needed = {"Authorization"}

    def __init__(self, app):
        super().__init__(app)

        self.registry_url = app.config.get("REGISTRY_SERVICE_URL")
        if not self.registry_url:
            raise ValueError("No REGISTRY_SERVICE_URL set.")

        self.client_cert_path = app.config.get("REGISTRY_SERVICE_CLIENT_CERT_PATH")
        if not self.client_cert_path:
            raise ValueError("No REGISTRY_SERVICE_CLIENT_CERT_PATH set.")

        self.client_key_path = app.config.get("REGISTRY_SERVICE_CLIENT_KEY_PATH")
        if not self.client_key_path:
            raise ValueError("No REGISTRY_SERVICE_CLIENT_KEY_PATH set.")

        self.ssl_verify = app.config.get("REGISTRY_SERVICE_SSL_VERIFY", True)
        self.cache_ttl = app.config.get("REGISTRY_AUTH_CACHE_TTL", 300)

    def _decode_basic_auth(self, header_value):
        """Decode a Basic Auth header value and return (username, password) or (None, None)."""
        try:
            encoded = header_value[len("Basic ") :]
            decoded = base64.b64decode(encoded).decode("utf-8")
        except Exception:
            return None, None

        separator = decoded.find(":")
        if separator < 0:
            return None, None

        return decoded[:separator], decoded[separator + 1 :]

    def _parse_registry_user(self, user):
        """Parse 'org_id|username' format. Returns (org_id, username) or (None, None)."""
        if not user or "|" not in user:
            return None, None

        org_id, username = user.split("|", 1)
        return org_id, username

    def process(self, context, backend_auth):
        self.app.logger.debug("Begin registry plugin processing")

        if "registry" not in backend_auth:
            self.app.logger.debug(
                'The back end does not have a "registry" authorization key defined. Skipping registry authorization plugin'
            )
            return context

        authorization = request.headers.get("Authorization")
        if not authorization or not authorization.startswith("Basic "):
            self.app.logger.debug(
                "Skipping registry authorization because the request did not have a Basic Authorization header"
            )
            return context

        user, password = self._decode_basic_auth(authorization)
        if user is None:
            self.app.logger.warning("Registry auth failed: malformed Basic Auth credentials")
            context.status_code = HTTPStatus.UNAUTHORIZED
            return context

        # Check cache for previously authenticated user (5-minute TTL)
        cache_key = f"registry_auth:{user}"
        cached_auth = cache.get(cache_key)
        if cached_auth:
            self.app.logger.debug(f"Registry auth cache hit for user: {user}")
        else:
            self.app.logger.debug(f"Registry auth cache miss for user: {user}")
            try:
                res = requests.post(
                    url=self.registry_url,
                    json={"credentials": {"username": user, "password": password}},
                    cert=(self.client_cert_path, self.client_key_path),
                    verify=self.ssl_verify,
                )
            except Exception as e:
                self.app.logger.error(f"Registry authentication request failed: {e}")
                context.status_code = HTTPStatus.UNAUTHORIZED
                return context

            if res.status_code != HTTPStatus.OK:
                self.app.logger.warning(f"Registry authentication returned status {res.status_code}")
                context.status_code = HTTPStatus.UNAUTHORIZED
                return context

            try:
                body = res.json()
                pull_access = body["access"]["pull"]
            except Exception:
                self.app.logger.warning("Registry authentication returned invalid response body")
                context.status_code = HTTPStatus.UNAUTHORIZED
                return context

            if pull_access != "granted":
                self.app.logger.warning("Registry authentication failed: pull access not granted")
                context.status_code = HTTPStatus.UNAUTHORIZED
                return context

            cache.set(key=cache_key, value=True, timeout=self.cache_ttl)
            self.app.logger.debug(f"Registry auth cached for user: {user}")

        org_id, username = self._parse_registry_user(user)

        auth_data = dict(org_id=org_id, username=username)
        context.auth = dict(auth_data=auth_data, auth_plugin=self)

        predicate = backend_auth["registry"]
        authorized = eval(predicate, dict(registry=auth_data))
        if not authorized:
            context.status_code = HTTPStatus.FORBIDDEN

        return context
