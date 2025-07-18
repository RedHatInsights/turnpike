from urllib.parse import urlparse

from flask import request, current_app
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from turnpike.views.saml.saml_settings_type import SAMLSettingsType


class SAMLContext:
    # A flag variable name to be stored in the session for when the initial request came from the VPN.
    session_request_vpn: str = "request_came_from_vpn"

    def __init__(self, saml_settings_type: SAMLSettingsType):
        """Create a SAML context with the required data for the OneLogin SAML authentication utility.

        :param saml_settings_type: The type of SAML settings the contex will work with.
        """

        # Prepare the required data by the OneLogin utility.
        url_data = urlparse(request.url)

        # The OneLogin utility uses the "http_host" setting to verify that the
        # data posted to the "/acs" endpoint by the SSO has a "Destination"
        # field that matches what we have set up here. We cannot use the
        # "X-Forwarded-Host" header that comes from Turnpike because the
        # hostname of the Nginx reverse proxy is different from the domains
        # we use to send requests to our internal applications.
        http_host: str
        if saml_settings_type == SAMLSettingsType.INTERNAL:
            http_host = current_app.config["INTERNAL_HOSTNAME"]
        else:
            http_host = current_app.config["PRIVATE_HOSTNAME"]

        self.request_data = {
            "get_data": request.args.copy(),
            "http_host": http_host,
            "https": "on" if request.scheme == "https" else "off",
            "post_data": request.form.copy(),
            "script_name": request.path,
            "server_port": url_data.port,
        }

        if saml_settings_type == SAMLSettingsType.INTERNAL:
            self.saml_authentication = OneLogin_Saml2_Auth(
                request_data=self.request_data, custom_base_path=current_app.config["INTERNAL_SAML_PATH"]
            )
        else:
            self.saml_authentication = OneLogin_Saml2_Auth(
                request_data=self.request_data, custom_base_path=current_app.config["PRIVATE_SAML_PATH"]
            )
