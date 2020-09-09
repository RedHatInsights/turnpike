import logging
from flask import request

from ..config import HEADER_CERTAUTH_SUBJECT, HEADER_CERTAUTH_ISSUER
from ..plugin import TurnpikeAuthPlugin

logger = logging.getLogger(__name__)


class X509AuthPlugin(TurnpikeAuthPlugin):
    name = "X509"
    principal_type = "X509"
    headers_needed = set([HEADER_CERTAUTH_SUBJECT, HEADER_CERTAUTH_ISSUER])

    def process(self, context, backend_auth):
        logger.debug("Begin X509 plugin processing")
        if "x509" in backend_auth and HEADER_CERTAUTH_SUBJECT in request.headers:
            auth_data = dict(
                subject_dn = request.headers[HEADER_CERTAUTH_SUBJECT],
                issuer_dn = request.headers.get(HEADER_CERTAUTH_ISSUER),
            )
            logger.debug(f"X509 auth_data: {auth_data}")
            context.auth = dict(auth_data=auth_data, auth_plugin=self)
            predicate = backend_auth["x509"]
            authorized = eval(predicate, dict(x509=auth_data))
            if not authorized:
                context.status_code = 403
        return context
