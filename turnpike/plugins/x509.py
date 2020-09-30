import logging
from flask import request

from ..plugin import TurnpikeAuthPlugin

logger = logging.getLogger(__name__)


class X509AuthPlugin(TurnpikeAuthPlugin):
    """
    X509AuthPlugin performs authorization on headers that represent an X509
    client certificate's identity. Subclasses may override the headers used
    by setting the `subject_header` and `issuer_header` attributes.
    """

    name = "X509"
    principal_type = "X509"

    def __init__(self, app):
        super().__init__(app)
        self.subject_header = self.app.config["HEADER_CERTAUTH_SUBJECT"]
        self.issuer_header = self.app.config["HEADER_CERTAUTH_ISSUER"]

    @property
    def headers_needed(self):
        return set([self.subject_header, self.issuer_header])

    def process(self, context, backend_auth):
        logger.debug("Begin X509 plugin processing")
        if "x509" in backend_auth and self.subject_header in request.headers:
            auth_data = dict(
                subject_dn=request.headers[self.subject_header], issuer_dn=request.headers.get(self.issuer_header)
            )
            logger.debug(f"X509 auth_data: {auth_data}")
            context.auth = dict(auth_data=auth_data, auth_plugin=self)
            predicate = backend_auth["x509"]
            authorized = eval(predicate, dict(x509=auth_data))
            if not authorized:
                context.status_code = 403
        return context
