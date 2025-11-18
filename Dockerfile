FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7-1763362218

ENV FLASK_RUN_HOST 0.0.0.0
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml

WORKDIR /usr/src/app

COPY Pipfile.lock /usr/src/app/

RUN microdnf install --nodocs -y gcc xmlsec1 python3.11 python3.11-pip python3.11-devel xmlsec1-openssl openssl

RUN python3.11 -m pip install --upgrade pip && \
    python3.11 -m pip install micropipenv && \
    python3.11 -m micropipenv install && \
    microdnf remove -y gcc

COPY . /usr/src/app/

CMD ["./run-server.sh"]
