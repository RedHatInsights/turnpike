import logging
import os

import redis
import yaml
from redis import Redis

SECRET_KEY = os.environ.get("SECRET_KEY")
CDN_PRESHARED_KEY = os.environ.get("CDN_PRESHARED_KEY")

if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set.")

SERVER_NAME = os.environ.get("SERVER_NAME")
TESTING = os.environ.get("TESTING", False)

# SAML settings {
#
# Begin with the paths where we will have our SAML client configurations. The
# OneLogin utility will assume that the certificates are in the "/certs"
# subdirectory of each location.
INTERNAL_SAML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saml/internal")
PRIVATE_SAML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saml/private")

# Finish with the hostnames to be used for the SAML verifications by the
# OneLogin utility.
INTERNAL_HOSTNAME = os.environ.get("INTERNAL_HOSTNAME")
PRIVATE_HOSTNAME = os.environ.get("PRIVATE_HOSTNAME")
# } // SAML settings

logging.info(f"Directory for the internal SAML settings set to {INTERNAL_SAML_PATH}")
logging.info(f"Directory for the private SAML settings set to {PRIVATE_SAML_PATH}")

SESSION_TYPE: str = "redis"
SESSION_REDIS: Redis = redis.Redis(host=os.environ.get("REDIS_HOST", "redis"))

WEB_ENV = os.environ.get("WEB_ENV", "dev")

# Cache configuration for Flask-Caching.
CACHE_TYPE: str = "RedisCache"
CACHE_REDIS_HOST: str = os.environ.get("REDIS_HOST", "redis")

PERMANENT_SESSION_LIFETIME = 60 * 60 * 4
SESSION_COOKIE_SECURE = True
MULTI_VALUE_SAML_ATTRS = os.environ.get("MULTI_VALUE_SAML_ATTRS", "").split(",")

HEADER_CERTAUTH_SUBJECT = os.environ.get("HEADER_CERTAUTH_SUBJECT", "x-rh-certauth-cn")
HEADER_CERTAUTH_ISSUER = os.environ.get("HEADER_CERTAUTH_ISSUER", "x-rh-certauth-issuer")
HEADER_CERTAUTH_PSK = os.environ.get("HEADER_CERTAUTH_PSK", None)

SSO_OIDC_HOST = os.environ.get("SSO_OIDC_HOST")
if not SSO_OIDC_HOST:
    raise ValueError("No SSO_OIDC_HOST set.")

SSO_OIDC_PORT = os.environ.get("SSO_OIDC_PORT")
if not SSO_OIDC_PORT:
    raise ValueError("No SSO_OIDC_PORT set.")

SSO_OIDC_PROTOCOL_SCHEME = os.environ.get("SSO_OIDC_PROTOCOL_SCHEME")
if not SSO_OIDC_PROTOCOL_SCHEME:
    raise ValueError("No SSO_OIDC_PROTOCOL_SCHEME set.")

SSO_OIDC_REALM = os.environ.get("SSO_OIDC_REALM")
if not SSO_OIDC_REALM:
    raise ValueError("No SSO_OIDC_REALM set.")

PLUGIN_CHAIN = [
    "turnpike.plugins.vpn.VPNPlugin",
    "turnpike.plugins.auth.AuthPlugin",
    "turnpike.plugins.source_ip.SourceIPPlugin",
    "turnpike.plugins.rh_identity.RHIdentityPlugin",
]

AUTH_PLUGIN_CHAIN = [
    "turnpike.plugins.oidc.oidc.OIDCAuthPlugin",
    "turnpike.plugins.saml.SAMLAuthPlugin",
    "turnpike.plugins.x509.X509AuthPlugin",
]

AUTH_DEBUG = os.environ.get("AUTH_DEBUG", False)

DEFAULT_RESPONSE_CODE = 200

with open(os.environ["BACKENDS_CONFIG_MAP"]) as ifs:
    BACKENDS = yaml.safe_load(ifs)
