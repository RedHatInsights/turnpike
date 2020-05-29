import os
from flask import Flask, request, make_response, url_for

from patches import RedHatSSOIdP, GatewayServiceProvider

app = Flask(__name__)
app.config.from_object("config")
app.secret_key = os.environ.get("SECRET_KEY")
sp = GatewayServiceProvider()
app.register_blueprint(sp.create_blueprint(), url_prefix="/saml/")


@app.route("/auth")
def auth():
    if request.headers.get("X-Original-Uri", "").startswith("/saml/"):
        return make_response("Authorized", 200)

    if sp.is_user_logged_in():
        auth_data = sp.get_auth_data_in_session()
        return make_response("Authorized", 200)
    else:
        next_url = request.headers.get("X-Original-Uri")
        login_url = url_for("flask_saml2_sp.login", next=next_url)

        resp = make_response("Unauthorized", 401)
        resp.headers["login_url"] = login_url
        return resp


#######################
### MOCKED SERVICES ###
#######################
@app.route("/api/ping-service/ping")
def ping():
    return make_response("PONG!", 200)
