#!/bin/bash
set -ex

echo "INSTALL DEPENDENCIES"
microdnf install --nodocs -y python39
pip3 install --upgrade pip
pip3 install micropipenv
micropipenv install

# #Run black/lint command
pip3 install black==25.1.0
if ! (black --check -l 119 -t py39 /var/workdir --diff); then
    echo "black formatter encountered an issue"
    exit 1
fi

echo "Run the unit tests"
pip3 install pytest
echo "RUN THE UNIT TESTS"
pytest --disable-pytest-warnings tests/
result=$?
if [ $result -ne 0 ]; then
    echo '====================================='
    echo '====  ✖  ERROR: PR_CHECK FAILED  ===='
    echo '====================================='
    exit 1
fi
