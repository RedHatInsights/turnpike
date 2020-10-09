import logging
from flask import request

from ..plugin import TurnpikeAuthPlugin


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
        self.cdn_psk = self.app.config.get("HEADER_CERTAUTH_PSK")

    @property
    def headers_needed(self):
        to_return = {self.subject_header, self.issuer_header}
        if self.cdn_psk:
            to_return.add(self.cdn_psk)
        return to_return

    def psk_check(self):
        """If HEADER_CERTAUTH_PSK is set in the config, then check that the
        request headers contain it and that its value matches the expected PSK."""
        return (not self.cdn_psk) or (
            self.cdn_psk in request.headers
            and request.headers[self.cdn_psk] == self.app.config.get("CDN_PRESHARED_KEY")
        )

    def process(self, context, backend_auth):
        self.app.logger.debug("Begin X509 plugin processing")
        if "x509" in backend_auth and self.subject_header in request.headers:
            if not self.psk_check():
                context.result += "CDN PSK was missing or invalid. "
                return context
            auth_data = dict(
                subject_dn=request.headers[self.subject_header], issuer_dn=request.headers.get(self.issuer_header)
            )
            context.auth = dict(auth_data=auth_data, auth_plugin=self)
            context.log_data.update(
                {
                    "x509.issuer.distinguished_name": auth_data["issuer_dn"],
                    "x509.subject.distinguished_name": auth_data["subject_dn"],
                }
            )
            predicate = backend_auth["x509"]
            authorized = eval(predicate, dict(x509=auth_data))
            if not authorized:
                context.result += "Failed x.509 authorization check. "
                context.status_code = 403
        return context
