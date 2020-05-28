import os
from flask_saml2.utils import certificate_from_file, private_key_from_file

IDP_CERTIFICATE = certificate_from_file('certs/idp-certificate.pem')
SP_CERTIFICATE = certificate_from_file('certs/sp-certificate.pem')
SP_PRIVATE_KEY = private_key_from_file('certs/sp-private-key.pem')
SECRET_KEY = os.environ.get('SECRET_KEY')

if not SECRET_KEY:
    raise ValueError('No SECRET_KEY set.')

SERVER_NAME = os.environ.get('SERVER_NAME')
SAML2_SP = {
    'certificate': SP_CERTIFICATE,
    'private_key': SP_PRIVATE_KEY,
}

SAML2_IDENTITY_PROVIDERS = [
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
