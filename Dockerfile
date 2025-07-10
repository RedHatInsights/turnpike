FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6-1750782676

ENV FLASK_RUN_HOST 0.0.0.0
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml

WORKDIR /usr/src/app

COPY Pipfile.lock /usr/src/app/

RUN microdnf install --nodocs -y gcc xmlsec1 python39 pip xmlsec1-openssl openssl libffi-devel
RUN pip3 install --upgrade pip && \
    pip3 install micropipenv && \
    micropipenv install && \
    microdnf remove -y gcc

COPY . /usr/src/app/

CMD ["./run-server.sh"]
