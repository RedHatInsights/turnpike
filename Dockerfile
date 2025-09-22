FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6-1758184547

ENV FLASK_RUN_HOST 0.0.0.0
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml

WORKDIR /usr/src/app

COPY Pipfile.lock /usr/src/app/

RUN microdnf install --nodocs -y gcc xmlsec1 python39 python3-devel pip xmlsec1-openssl openssl

RUN pip3 install --upgrade pip && \
    pip3 install micropipenv && \
    micropipenv install && \
    microdnf remove -y gcc

COPY . /usr/src/app/

CMD ["./run-server.sh"]
