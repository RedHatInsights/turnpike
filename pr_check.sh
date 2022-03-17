#!/bin/bash

set -exv

export LC_ALL=en_US.utf-8
export LANG=en_US.utf-8

python3 -m venv .
source bin/activate
bin/pip3 install --upgrade pip pipenv
bin/pipenv install -d
bin/pre-commit run -a
bin/pytest
