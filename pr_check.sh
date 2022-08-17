#!/bin/bash

export CONTAINER_NAME="turnpike-pr-check"
export IMAGE_TAG="turnpike:pr-check"
export NGINX_IMAGE="quay.io/cloudservices/turnpike-nginx"
export WEB_IMAGE="quay.io/cloudservices/turnpike-web"
export PR_IMAGE_TAG=$(git rev-parse --short=7 HEAD)

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
bin/pip3 install black pre-commit

# Run pre-commit
if ! (pre-commit run -a); then
    echo "pre-commit ecountered an issue"
    exit 1
fi

# Build PR_CHECK Image
podman build --no-cache -f Dockerfile-pr-check --tag $IMAGE_TAG

# Build PR_Check Container
podman create --name $CONTAINER_NAME $IMAGE_TAG

# Build a PR image to deploy
podman login -u="$QUAY_USER" -p="$QUAY_TOKEN" quay.io

podman build -t "${NGINX_IMAGE}:${PR_IMAGE_TAG}" nginx
podman push "${NGINX_IMAGE}:${PR_IMAGE_TAG}"

podman build -t "${WEB_IMAGE}:${PR_IMAGE_TAG}" .
podman push "${WEB_IMAGE}:${PR_IMAGE_TAG}"

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
