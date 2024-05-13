#!/bin/bash

export CONTAINER_NAME="turnpike-pr-check"
export IMAGE_TAG="turnpike:pr-check"

function teardown_podman() {
    podman rm -f $CONTAINER_NAME || true
    podman image rm -f $IMAGE_TAG || true
}

# Catches process termination and cleans up Podman artifacts
trap "teardown_podman" EXIT SIGINT SIGTERM

set -ex

# Setup environment for pre-commit check
python3 -m venv .
source bin/activate
pip install pipenv
pip install pre-commit

# Run pre-commit
if ! (pre-commit run -av); then
    echo "pre-commit ecountered an issue"
    exit 1
fi

# Build PR_CHECK Image
podman build --no-cache -f Dockerfile-pr-check --tag $IMAGE_TAG

# Build PR_Check Container
podman create --name $CONTAINER_NAME $IMAGE_TAG

# Run PR_CHECK Container (attached with standard output)
# and reports if the Containerized PR_Check fails
if ! (podman start -a $CONTAINER_NAME); then
    echo "Test failure observed; aborting"
    exit 1
fi

# Pass Jenkins dummy artifacts as it needs
# an xml output to consider the job a success.
mkdir -p $WORKSPACE/artifacts
cat << EOF > $WORKSPACE/artifacts/junit-dummy.xml
<testsuite tests="1">
    <testcase classname="dummy" name="dummytest"/>
</testsuite>
EOF
