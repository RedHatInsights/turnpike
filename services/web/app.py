import os
from flask import Flask, request, make_response, url_for, session
from datetime import timedelta

from flask_saml2.sp import ServiceProvider, IdPHandler
from flask_saml2.utils import certificate_from_file, private_key_from_file
from flask_saml2.sp.idphandler import AuthData

IDP_CERTIFICATE = certificate_from_file('certs/idp-certificate.pem')
CERTIFICATE = certificate_from_file('certs/sp-certificate.pem')
PRIVATE_KEY = private_key_from_file('certs/sp-private-key.pem')
SECRET_KEY = os.environ.get('SECRET_KEY')

if not SECRET_KEY:
    raise ValueError('No SECRET_KEY set.')

class RedHatSSOIdP(IdPHandler):
    pass

class GatewayServiceProvider(ServiceProvider):
    def get_logout_return_url(self):
        return url_for('auth', _external=True)

    def get_default_login_return_url(self):
        return url_for('auth', _external=True)


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config['SERVER_NAME'] = 'nginx:8080'

app.config['SAML2_SP'] = {
    'certificate': CERTIFICATE,
    'private_key': PRIVATE_KEY,
}

app.config['SAML2_IDENTITY_PROVIDERS'] = [
    {
        'CLASS': 'app.RedHatSSOIdP',
        'OPTIONS': {
            'display_name': os.environ.get('IDP_NAME'),
            'entity_id': os.environ.get('ENTITY_ID'),
            'sso_url': os.environ.get('SSO_URL'),
            'slo_url': os.environ.get('SLO_URL'),
            'certificate': IDP_CERTIFICATE,
        },
    },
]

sp = GatewayServiceProvider()
app.register_blueprint(sp.create_blueprint(), url_prefix='/saml/')

@app.route('/auth')
def auth():
    if request.headers.get('X-Original-Uri', '').startswith('/saml/'):
        return make_response('Authorized', 200)

    if sp.is_user_logged_in():
        auth_data = sp.get_auth_data_in_session()
        return make_response('Authorized', 200)
    else:
        next_url = request.headers.get("X-Original-Uri")
        login_url = url_for('flask_saml2_sp.login', next=next_url)

        resp = make_response('Unauthorized', 401)
        resp.headers['login_url'] = login_url
        return resp

#######################
### MOCKED SERVICES ###
#######################
@app.route('/api/ping-service/ping')
def ping():
    return make_response('PONG!', 200)
