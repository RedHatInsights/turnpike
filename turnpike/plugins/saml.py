import contextlib
from typing import Optional
from urllib.parse import urlparse

from flask import Blueprint, abort, current_app, make_response, redirect, request, session, views, url_for, Request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from requests.exceptions import InvalidHeader

from .common.AllowedNetworks import AllowedNetworks
from .common.header_validator import HeaderValidator
from ..plugin import TurnpikeAuthPlugin

blueprint = Blueprint("saml", __name__, url_prefix="/saml")


class Context:
    def __init__(self, request_data: dict, auth: OneLogin_Saml2_Auth):
        self.request_data = request_data
        self.auth = auth


class SAMLView(views.MethodView):
    # A flag variable name to be stored in the session for when the initial request came from the VPN.
    session_request_vpn: str = "request_came_from_vpn"

    def __init__(self):
        self.header_validator = HeaderValidator(app=current_app)

    def __init_saml_auth__(self, request_data: dict):
        """Initiate the OneLogin SAML authentication utility.

        Since the SAML authentication works with a bunch of requests and
        redirects, we use a session to store the state of the authentication
        process between requests.

        Since we are not sure if the Service Provider will return any custom
        headers like the "VPN" header, we can use the session to identify if
        any request was originated from the VPN network. Usually the "login"
        one is the one that will be setting the session's "came from the VPN
        key".

        This way, we can use the correct SAML settings to perform the
        authentication.

        :param request_data: A dictionary containing the required data by the
        OneLogin utility.
        """
        # Validate the "edge host" header if it is present.
        edge_host_header: Optional[str] = request.headers.get(HeaderValidator.EDGE_HOST_HEADER)
        if edge_host_header:
            network: Optional[AllowedNetworks] = None
            try:
                network = self.header_validator.validate_edge_host_header(edge_host_header)
            except InvalidHeader as ih:
                current_app.logger.warning(
                    f'[{self.header_validator.EDGE_HOST_HEADER}: "{edge_host_header}"] Invalid "edge host" header specified: {ih}'
                )

            # Only set up the session flag when the request came from a
            # private network.
            if network == AllowedNetworks.PRIVATE:
                session[self.session_request_vpn] = True

        if session.get(self.session_request_vpn):
            current_app.logger.debug(
                f'[{self.header_validator.EDGE_HOST_HEADER}: "{edge_host_header}"] Using private SAML settings'
            )

            return OneLogin_Saml2_Auth(
                request_data=request_data, custom_base_path=current_app.config["PRIVATE_SAML_PATH"]
            )
        else:
            current_app.logger.debug(
                f'[{self.header_validator.EDGE_HOST_HEADER}: "{edge_host_header}"] Using internal SAML settings'
            )

            return OneLogin_Saml2_Auth(
                request_data=request_data, custom_base_path=current_app.config["INTERNAL_SAML_PATH"]
            )

    def __prepare_flask_request__(self, req: Request):
        url_data = urlparse(req.url)
        return {
            "https": "on" if req.scheme == "https" else "off",
            "http_host": req.headers.get("X-Forwarded-Host", req.headers.get("Host", "")),
            "server_port": url_data.port,
            "script_name": req.path,
            "get_data": req.args.copy(),
            "post_data": req.form.copy(),
        }

    @contextlib.contextmanager
    def saml_context(self):
        request_data = self.__prepare_flask_request__(request)
        auth_utility = self.__init_saml_auth__(request_data)

        yield Context(request_data=request_data, auth=auth_utility)


class MetadataView(SAMLView):
    def get(self):
        with self.saml_context() as ctx:
            settings = ctx.auth.get_settings()
            metadata = settings.get_sp_metadata()
            errors = settings.validate_metadata(metadata)

            if len(errors) == 0:
                resp = make_response(metadata, 200)
                resp.headers["Content-Type"] = "text/xml"
            else:
                resp = make_response(", ".join(errors), 500)
            return resp


class LoginView(SAMLView):
    def get(self):
        with self.saml_context() as ctx:
            next_url = request.args.get("next", "/")
            return redirect(ctx.auth.login(next_url))


class ACSView(SAMLView):
    def post(self):
        with self.saml_context() as ctx:
            request_id = None
            if "AuthNRequestID" in session:
                request_id = session["AuthNRequestID"]
            ctx.auth.process_response(request_id=request_id)
            errors = ctx.auth.get_errors()
            if len(errors) == 0:
                if "AuthNRequestID" in session:
                    del session["AuthNRequestID"]
                session["samlUserdata"] = ctx.auth.get_attributes()
                session["samlSessionIndex"] = ctx.auth.get_session_index()
                self_url = OneLogin_Saml2_Utils.get_self_url(ctx.request_data)
                if "RelayState" in request.form and self_url != request.form["RelayState"]:
                    relay_state = ctx.auth.redirect_to(request.form["RelayState"])
                    current_app.logger.debug(f"Redirecting to {relay_state}")
                    return redirect(relay_state)
                else:
                    current_app.logger.debug("Redirecting to index")
                    return redirect("/")
            else:
                if ctx.auth.get_settings().is_debug_active():
                    error_reason = ctx.auth.get_last_error_reason()
                else:
                    error_reason = ""
                resp = make_response(error_reason, 500)
                resp.headers["Content-Type"] = "text/plain"
                return resp


class SLSView(SAMLView):
    def get(self):
        with self.saml_context() as ctx:
            request_id = None
            if "LogoutRequestID" in session:
                request_id = session["LogoutRequestID"]
            url = ctx.auth.process_slo(request_id=request_id, delete_session_cb=session.clear)
            errors = ctx.auth.get_errors()
            if len(errors) == 0:
                if url is not None:
                    return redirect(url)
                else:
                    return redirect("/")
            else:
                if ctx.auth.get_settings().is_debug_active():
                    error_reason = ctx.auth.get_last_error_reason()
                else:
                    error_reason = ""
                resp = make_response(error_reason, 500)
                resp.headers["Content-Type"] = "text/plain"
                return resp


class MockSAMLAssertionView(views.MethodView):
    def post(self):
        if not current_app.config.get("TESTING"):
            abort(404)
        if request.mimetype != "application/json":
            return make_response("Content type must be application/json", 415)
        saml_user_data = request.json
        session["samlUserdata"] = saml_user_data
        session["samlSessionIndex"] = -1
        return make_response("", 204)


blueprint.add_url_rule("/metadata.xml", view_func=MetadataView.as_view("saml-metadata"))
blueprint.add_url_rule("/login/", view_func=LoginView.as_view("saml-login"))
blueprint.add_url_rule("/acs/", view_func=ACSView.as_view("saml-acs"))
blueprint.add_url_rule("/sls/", view_func=SLSView.as_view("saml-sls"))
blueprint.add_url_rule("/mock/", view_func=MockSAMLAssertionView.as_view("saml-mock"))


class SAMLAuthPlugin(TurnpikeAuthPlugin):
    name = "saml-auth"
    principal_type = "Associate"

    def register_blueprint(self):
        self.app.register_blueprint(blueprint)

    def login_url(self):
        next_url = request.headers.get("X-Original-Uri")
        return url_for("saml.saml-login", next=next_url)

    def process(self, context, backend_auth):
        current_app.logger.debug("Begin SAML Auth plugin processing")
        if "saml" in backend_auth and "samlUserdata" in session:
            auth_dict = session["samlUserdata"]
            auth_tuples = auth_dict.items()
            if current_app.config["AUTH_DEBUG"]:
                current_app.logger.info(f"SAML auth_data: {auth_tuples}")
            multi_value_attrs = self.app.config["MULTI_VALUE_SAML_ATTRS"]
            context.auth = dict(
                auth_data={k: v if (len(v) > 1 or (k in multi_value_attrs)) else v[0] for k, v in auth_tuples},
                auth_plugin=self,
            )
            predicate = backend_auth["saml"]
            authorized = eval(predicate, dict(user=auth_dict))
            if not authorized:
                context.status_code = 403
        return context
