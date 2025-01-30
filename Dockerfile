FROM registry.access.redhat.com/ubi8/ubi-minimal:8.10-1179

WORKDIR /usr/src/app

ENV FLASK_RUN_HOST 0.0.0.0

ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml

COPY ./requirements.txt /usr/src/app/

RUN microdnf install -y dnf && \
    dnf install -y dnf-plugins-core && \
    # Enabling RH "CodeReady Builder" to provide the same libraries and developer tools to the UBI image as "Powertools" does for CentOS.
    dnf config-manager --set-enable ubi-8-codeready-builder-rpms && \
    dnf install -y gcc xmlsec1 python39 xmlsec1-openssl openssl python39-devel && \
    pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt && \
    dnf remove -y gcc python39-devel && \
    rm -rf /var/lib/dnf /var/cache/dnf

COPY . /usr/src/app/

CMD ["./run-server.sh"]
