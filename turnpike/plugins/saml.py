import contextlib
from urllib.parse import urlparse

from flask import Blueprint, abort, current_app, make_response, redirect, request, session, views, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from ..plugin import TurnpikeAuthPlugin

blueprint = Blueprint("saml", __name__, url_prefix="/saml")


class Context:
    req = None
    auth = None


class SAMLView(views.MethodView):
    def __init_saml_auth__(self, req):
        saml_path = current_app.config["SAML_PATH"]
        auth = OneLogin_Saml2_Auth(req, custom_base_path=saml_path)
        return auth

    def __prepare_flask_request__(self, request):
        url_data = urlparse(request.url)
        return {
            "https": "on" if request.scheme == "https" else "off",
            "http_host": request.headers.get("X-Forwarded-Host", request.headers.get("Host", "")),
            "server_port": url_data.port,
            "script_name": request.path,
            "get_data": request.args.copy(),
            "post_data": request.form.copy(),
        }

    @contextlib.contextmanager
    def saml_context(self):
        ctx = Context()
        ctx.req = self.__prepare_flask_request__(request)
        ctx.auth = self.__init_saml_auth__(ctx.req)
        yield ctx


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
                self_url = OneLogin_Saml2_Utils.get_self_url(ctx.req)
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
            current_app.logger.debug(f"SAML auth_data: {auth_tuples}")
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
