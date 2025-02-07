FROM registry.access.redhat.com/ubi8/ubi-minimal:8.10-1179

ENV FLASK_RUN_HOST 0.0.0.0
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml

WORKDIR /usr/src/app

COPY Pipfile.lock /usr/src/app/

RUN microdnf install --nodocs -y gcc xmlsec1 python39 xmlsec1-openssl openssl
RUN pip3 install --upgrade pip && \
    pip3 install micropipenv && \
    micropipenv install && \
    microdnf remove -y gcc

COPY . /usr/src/app/

CMD ["./run-server.sh"]
