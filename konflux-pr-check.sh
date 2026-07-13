#!/bin/bash
set -ex

echo "INSTALL DEPENDENCIES"
microdnf install --nodocs -y gcc python3-devel xmlsec1
python3 -m pip install --upgrade pip
python3 -m pip install micropipenv
micropipenv install

# #Run black/lint command
python3 -m pip install black==26.1.0
if ! (black --check -l 119 -t py312 /var/workdir --diff); then
    echo "black formatter encountered an issue"
    exit 1
fi

echo "Run the unit tests"
python3 -m pip install pytest
echo "RUN THE UNIT TESTS"
pytest --disable-pytest-warnings tests/
result=$?
if [ $result -ne 0 ]; then
    echo '====================================='
    echo '====  ✖  ERROR: PR_CHECK FAILED  ===='
    echo '====================================='
    exit 1
fi
