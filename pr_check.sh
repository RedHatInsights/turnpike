#!/bin/bash

set -exv

dnf config-manager --set-enable codeready-builder-for-rhel-8-x86_64-rpms
dnf install -y libxml2-devel xmlsec1-devel xmlsec1-openssl-devel libtool-ltdl-devel

python3 -m venv .
source bin/activate
bin/pip3 install --upgrade pip pipenv
bin/pipenv install wheel
bin/pipenv install -d
bin/pre-commit run -a
bin/pytest
