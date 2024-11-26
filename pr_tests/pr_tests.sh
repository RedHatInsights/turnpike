#!/bin/bash

set -ex

pip3 install --upgrade pip
pip3 install pytest
pytest --disable-pytest-warnings tests/
result=$?

if [ $result -ne 0 ]; then
    echo '====================================='
    echo '====  ✖  ERROR: PR_CHECK FAILED  ===='
    echo '====================================='
    exit 1
fi

# Setup environment for pre-commit check
pip3 install pre-commit
# Run pre-commit
if ! (pre-commit run -av); then
    echo "pre-commit ecountered an issue"
    exit 1
fi
