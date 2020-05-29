from flask import url_for
from flask_saml2.sp import ServiceProvider, IdPHandler


class RedHatSSOIdP(IdPHandler):
    pass


class GatewayServiceProvider(ServiceProvider):
    def get_logout_return_url(self):
        return url_for("auth", _external=True)

    def get_default_login_return_url(self):
        return url_for("auth", _external=True)
