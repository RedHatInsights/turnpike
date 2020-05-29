# Turnpike

## Overview
This is an internal gateway used to authenticate Red Hat associates against internal
Red Hat SSO, along with an auth/policy service to handle SAML authentication and
provide ACL-based authorization.

## Local development

### Setup your .env
There is a `.env.example` file which can be used as a starter for your local `.env`

### Dependencies
Install the local pip dependencies (e.g.: `pipenv install`)

In order to fully test the stack, you'll need the following setup:
- an IdP (you can use the simple example IdP from the [flask-saml2 project](https://github.com/timheap/flask-saml2/blob/master/examples/idp.py))
- the following environment variables setup in your `.env`:
```
ENTITY_ID # the endpoint of your IdP to expose metadata
SSO_URL # the SAML login URL of your IdP
SLO_URL # the SAML logout URL of your IdP
```
- the following certs (locally if you're using the flask-saml2 example IdP, you can use the [certs from the example](https://github.com/timheap/flask-saml2/tree/master/tests/keys/sample)):
```
services/web/certs/idp-certificate.pem # cert for the IdP
services/web/certs/sp-certificate.pem # cert for the SP
services/web/certs/sp-private-key.pem # private key for the SP
```

### Start/stop the gateway and auth service with Docker Compose
```
$ ./scripts/start
$ ./scripts/stop
```

## Testing
To run local unit tests:
```
$ pytest
```

## Linting/pre-commit
Linting will run automatically with `black` in a pre-commit hook, but you'll need to run `pre-commit install` first.

## Resources
Documentation for `flask-saml2`: https://flask-saml2.readthedocs.io/en/latest/sp/configuration.html
