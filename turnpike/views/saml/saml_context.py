from urllib.parse import urlparse

from flask import request, session, current_app
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from turnpike.plugins.vpn import VPNPlugin


class SAMLContext:
    # A flag variable name to be stored in the session for when the initial request came from the VPN.
    session_request_vpn: str = "request_came_from_vpn"

    def __init__(self):
        # Prepare the required data by the OneLogin utility.
        url_data = urlparse(request.url)
        self.request_data = {
            "get_data": request.args.copy(),
            "http_host": request.headers.get("X-Forwarded-Host", request.headers.get("Host", "")),
            "https": "on" if request.scheme == "https" else "off",
            "post_data": request.form.copy(),
            "script_name": request.path,
            "server_port": url_data.port,
        }

        # Since the SAML authentication works with a bunch of requests and
        # redirects, we use a session to store the state of the authentication
        # process between requests.
        #
        # Since we are not sure if the Service Provider will return any custom
        # headers like the "VPN" header, we can use the session to identify if
        # any request was originated from the VPN network. Usually the "login"
        # one is the one that will be setting the session's "came from the VPN
        # key".
        #
        # This way, we can use the correct SAML settings to perform the
        # authentication.
        #
        # :param request_data: A dictionary containing the required data by the
        # OneLogin utility.
        if request.headers.get(VPNPlugin.edge_host_header):
            session[self.session_request_vpn] = True

        if session.get(self.session_request_vpn):
            self.saml_authentication = OneLogin_Saml2_Auth(
                request_data=self.request_data, custom_base_path=current_app.config["PRIVATE_SAML_PATH"]
            )
        else:
            self.saml_authentication = OneLogin_Saml2_Auth(
                request_data=self.request_data, custom_base_path=current_app.config["GENERAL_SAML_PATH"]
            )
