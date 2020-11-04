#!/bin/bash

set -exv

NGINX_IMAGE="quay.io/cloudservices/turnpike-nginx"
WEB_IMAGE="quay.io/cloudservices/turnpike-web"
NGINX_PROMETHEUS_IMAGE="quay.io/cloudservices/turnpike-nginx-prometheus"
IMAGE_TAG=$(git rev-parse --short=7 HEAD)

if [[ -z "$QUAY_USER" || -z "$QUAY_TOKEN" ]]; then
    echo "QUAY_USER and QUAY_TOKEN must be set"
    exit 1
fi

DOCKER_CONF="$PWD/.docker"
mkdir -p "$DOCKER_CONF"
docker --config="$DOCKER_CONF" login -u="$QUAY_USER" -p="$QUAY_TOKEN" quay.io

docker --config="$DOCKER_CONF" build -t "${NGINX_IMAGE}:${IMAGE_TAG}" nginx
docker --config="$DOCKER_CONF" build -t "${WEB_IMAGE}:${IMAGE_TAG}" .
docker --config="$DOCKER_CONF" build -f ./nginx/Dockerfile-prometheus -t "${NGINX_PROMETHEUS_IMAGE}:${IMAGE_TAG}" .

docker --config="$DOCKER_CONF" push "${NGINX_IMAGE}:${IMAGE_TAG}"
docker --config="$DOCKER_CONF" push "${WEB_IMAGE}:${IMAGE_TAG}"
docker --config="$DOCKER_CONF" push "${NGINX_PROMETHEUS_IMAGE}:${IMAGE_TAG}"
