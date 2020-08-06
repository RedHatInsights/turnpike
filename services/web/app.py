import base64
import contextlib
import json
import os
from urllib.parse import urlparse

from flask import Flask, request, make_response, url_for, session, views, redirect
from healthcheck import HealthCheck
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
import yaml

from logging.config import dictConfig

dictConfig(
    {
        "version": 1,
        "formatters": {"default": {"format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s"}},
        "handlers": {
            "console": {"class": "logging.StreamHandler", "formatter": "default", "level": "DEBUG"},
            "wsgi": {
                "class": "logging.StreamHandler",
                "stream": "ext://flask.logging.wsgi_errors_stream",
                "formatter": "default",
                "level": "DEBUG",
            },
        },
        "root": {"level": "DEBUG" if os.environ.get("FLASK_ENV") == "development" else "INFO", "handlers": ["wsgi"]},
    }
)

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config.from_object("config")

session_obj = Session()
session_obj.init_app(app)


class Context:
    req = None
    auth = None


class SAMLView(views.MethodView):
    def __init__(self, saml_path):
        self.saml_path = saml_path

    def __init_saml_auth__(self, req):
        auth = OneLogin_Saml2_Auth(req, custom_base_path=self.saml_path)
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
                session["samlNameId"] = ctx.auth.get_nameid()
                session["samlNameIdFormat"] = ctx.auth.get_nameid_format()
                session["samlNameIdNameQualifier"] = ctx.auth.get_nameid_nq()
                session["samlNameIdSPNameQualifier"] = ctx.auth.get_nameid_spnq()
                session["samlSessionIndex"] = ctx.auth.get_session_index()
                self_url = OneLogin_Saml2_Utils.get_self_url(ctx.req)
                if "RelayState" in request.form and self_url != request.form["RelayState"]:
                    relay_state = ctx.auth.redirect_to(request.form["RelayState"])
                    app.logger.debug(f"Redirecting to {relay_state}")
                    return redirect(relay_state)
                else:
                    app.logger.debug("Redirecting to index")
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
                if auth.get_settings().is_debug_active():
                    error_reason = auth.get_last_error_reason()
                else:
                    error_reason = ""
                resp = make_response(error_reason, 500)
                resp.headers["Content-Type"] = "text/plain"
                return resp


class AuthView(views.MethodView):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.backends = dict()
        with open(os.environ["BACKENDS_CONFIG_MAP"]) as ifs:
            backends_list = yaml.safe_load(ifs)
        for backend in backends_list:
            if "auth" in backend:
                self.backends[backend["route"]] = backend["auth"]

    def make_identity_header(self, identity_type, auth_type, auth_data):
        header_data = dict(
            identity=dict(type=identity_type, auth_type=auth_type, **{identity_type.lower(): auth_data})
        )
        app.logger.debug(header_data)
        return base64.encodebytes(json.dumps(header_data).encode("utf8")).replace(b"\n", b"")

    def auth_saml(self, auth):
        if "samlUserdata" in session:
            auth_data = session["samlUserdata"].items()
            app.logger.debug(f"SAML auth_data: {auth_data}")
            predicate = auth["saml"]
            authorized = eval(predicate, dict(user=auth_data))
            if authorized:
                resp = make_response("Authorized", 200)
                resp.headers["X-RH-Identity"] = self.make_identity_header(
                    "Associate", "saml-auth", {k: v if len(v) > 1 else v[0] for k, v in auth_data}
                )
                return resp
            else:
                return make_response("Forbidden", 403)
        else:
            next_url = request.headers.get("X-Original-Uri")
            login_url = url_for("saml-login", next=next_url)

            resp = make_response("Unauthorized", 401)
            resp.headers["login_url"] = login_url
            return resp

    def get(self):
        app.logger.debug("Begin auth")
        original_url = request.headers["X-Original-Uri"]
        matches = [route for route in self.backends.keys() if original_url.startswith(route)]
        backend_name = max(matches, key=lambda match: len(match))
        app.logger.debug(f"Matched backend: {backend_name}")
        backend = self.backends[backend_name]
        if "saml" in backend:
            return self.auth_saml(backend)
        # elif 'x509' in backend:
        #    (Once we have mTLS auth ready)


app.add_url_rule("/saml/metadata.xml", view_func=MetadataView.as_view("saml-metadata", app.config["SAML_PATH"]))
app.add_url_rule("/saml/login/", view_func=LoginView.as_view("saml-login", app.config["SAML_PATH"]))
app.add_url_rule("/saml/acs/", view_func=ACSView.as_view("saml-acs", app.config["SAML_PATH"]))
app.add_url_rule("/saml/sls/", view_func=SLSView.as_view("saml-sls", app.config["SAML_PATH"]))
app.add_url_rule("/auth/", view_func=AuthView.as_view("auth"))

health = HealthCheck()

app.add_url_rule("/_healthcheck/", view_func=health.run)

#######################
### MOCKED SERVICES ###
#######################
@app.route("/api/ping-service/ping")
def ping():
    return make_response("PONG!", 200)
