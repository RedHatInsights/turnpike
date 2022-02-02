import os
import redis
import yaml

SECRET_KEY = os.environ.get("SECRET_KEY")
CDN_PRESHARED_KEY = os.environ.get("CDN_PRESHARED_KEY")

if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set.")

SERVER_NAME = os.environ.get("SERVER_NAME")
TESTING = os.environ.get("TESTING", False)
SAML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saml")

SESSION_TYPE = "redis"
SESSION_REDIS = redis.Redis(
    host=os.environ.get("REDIS_HOST", "redis"),
    username=os.environ.get("REDIS_USERNAME"),
    password=os.environ.get("REDIS_PASSWORD"),
)
PERMANENT_SESSION_LIFETIME = 60 * 60 * 4
SESSION_COOKIE_SECURE = True
MULTI_VALUE_SAML_ATTRS = os.environ.get("MULTI_VALUE_SAML_ATTRS", "").split(",")

HEADER_CERTAUTH_SUBJECT = os.environ.get("HEADER_CERTAUTH_SUBJECT", "x-rh-certauth-cn")
HEADER_CERTAUTH_ISSUER = os.environ.get("HEADER_CERTAUTH_ISSUER", "x-rh-certauth-issuer")
HEADER_CERTAUTH_PSK = os.environ.get("HEADER_CERTAUTH_PSK", None)

# URI to the JWT certificates used for validating
# i.e. https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs
JWT_OIDC_JWKS_URI = os.environ.get("JWT_OIDC_JWKS_URI", "")
JWT_OIDC_SUPPORTED_ALGORITHMS = os.environ.get("JWT_OIDC_SUPPORTED_ALGORITHMS", "").split(",")

PLUGIN_CHAIN = [
    "turnpike.plugins.auth.AuthPlugin",
    "turnpike.plugins.source_ip.SourceIPPlugin",
    "turnpike.plugins.rh_identity.RHIdentityPlugin",
]

AUTH_PLUGIN_CHAIN = ["turnpike.plugins.x509.X509AuthPlugin", "turnpike.plugins.saml.SAMLAuthPlugin", "turnpike.plugins.jwt_oidc.JWTODICAuthPlugin"]
AUTH_DEBUG = os.environ.get("AUTH_DEBUG", False)

DEFAULT_RESPONSE_CODE = 200

with open(os.environ["BACKENDS_CONFIG_MAP"]) as ifs:
    BACKENDS = yaml.safe_load(ifs)
