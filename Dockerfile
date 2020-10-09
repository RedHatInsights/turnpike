FROM quay.io/app-sre/centos:8

WORKDIR /usr/src/app

ENV FLASK_RUN_HOST 0.0.0.0
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml
COPY ./Pipfile ./Pipfile.lock /usr/src/app/
RUN dnf install -y dnf-plugins-core && \
    dnf config-manager --set-enabled PowerTools && \
    dnf install -y gcc xmlsec1 xmlsec1-devel python3-pip python36 python3-devel libtool-ltdl-devel xmlsec1-openssl xmlsec1-openssl-devel openssl && \
    pip3 install --no-cache-dir --upgrade pip pipenv && \
    pipenv lock --requirements > requirements.txt && \
    pip install --no-cache-dir -r requirements.txt && \
    dnf remove -y gcc python3-devel && \
    rm -rf /var/lib/dnf /var/cache/dnf && \
    curl -L -o /usr/bin/haberdasher https://github.com/RedHatInsights/haberdasher/releases/latest/download/haberdasher_linux_amd64 && \
    chmod 755 /usr/bin/haberdasher
COPY . /usr/src/app/
ENTRYPOINT ["/usr/bin/haberdasher"]
CMD ["./run-server.sh"]
