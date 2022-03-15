#!/bin/bash

set -exv

python3 -m venv .
source bin/activate
bin/pip3 install --upgrade pip pipenv
bin/pipenv install wheel
bin/pipenv install -d
bin/pre-commit run -a
bin/pytest
