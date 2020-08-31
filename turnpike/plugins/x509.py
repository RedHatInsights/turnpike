import logging
from flask import request

from ..plugin import TurnpikeAuthPlugin

logger = logging.getLogger(__name__)


class X509AuthPlugin(TurnpikeAuthPlugin):
    name = "X509"
    principal_type = "X509"
    headers_needed = set(["x-rh-certauth-cn", "x-rh-certauth-issuer"])

    def process(self, context, backend_auth):
        logger.debug("Begin X509 plugin processing")
        if "x509" in backend_auth and 'x-rh-certauth-cn' in request.headers:
            auth_data = dict(
                subject_dn = request.headers['x-rh-certauth-cn'],
                issuer_dn = request.headers.get('x-rh-certauth-issuer'),
            )
            logger.debug(f"X509 auth_data: {auth_data}")
            context.auth = dict(auth_data=auth_data, auth_plugin=self)
            predicate = backend_auth["x509"]
            authorized = eval(predicate, dict(x509=auth_data))
            if not authorized:
                context.status_code = 403
        return context
