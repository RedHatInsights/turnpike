import os

SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise ValueError("No SECRET_KEY set.")

SERVER_NAME = os.environ.get("SERVER_NAME")
SAML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "saml")
