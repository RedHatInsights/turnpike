# Turnpike

## Overview
This is an internal gateway used to authenticate Red Hat associates against internal
Red Hat SSO or mTLS, along with an auth/policy service to handle SAML authentication and
provide ACL-based authorization.

## Setup and configuration

See `docs/` for instructions on setting up your environment.

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
