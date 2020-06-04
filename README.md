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

In order to fully test the stack, you'll need to do the following:
- Select or configure an IdP. You can use the reference IdP available at https://samltest.id/
- Obtain an SSL certificate with your hostname (e.g. from LetsEncrypt) or generate one
- Put a copy in `services/nginx/certs` as the files `cert.pem` and `key.pem`
- Configure the `python3-saml` library in `services/web/saml` with your IdP and cert
  - documentation [here](https://github.com/onelogin/python3-saml#how-it-works)
  - Your SP entity ID is  `https://<hostname>/saml/metadata.xml`
  - Your ACS URL is `https://<hostname>/saml/acs/`
  - Your SLS URL is `https://<hostname>/saml/sls/`

A successful test should return "PONG" when you hit `https://<hostname>/api/ping-service/ping` in your browser.

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
Linting will run automatically with `black` in a pre-commit hook, but you'll need to run `pre-commit install` first. You can also run it manually with `pre-commit run -a`.

## Resources
Documentation for `flask-saml2`: https://flask-saml2.readthedocs.io/en/latest/sp/configuration.html
