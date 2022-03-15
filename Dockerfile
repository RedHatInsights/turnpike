FROM registry.access.redhat.com/ubi8-minimal

WORKDIR /usr/src/app

ENV FLASK_RUN_HOST 0.0.0.0
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml
COPY ./Pipfile ./Pipfile.lock /usr/src/app/
RUN microdnf install -y dnf && \
    dnf install -y dnf-plugins-core && \
    # Enabling RH "CodeReady Builder" to provide the same libraries and developer tools to the UBI image as "Powertools" does for CentOS.
    dnf config-manager --set-enable codeready-builder-for-rhel-8-x86_64-rpms && \
    dnf install -y gcc xmlsec1 xmlsec1-devel python3-pip python36 python3-devel libxml2-devel libtool-ltdl-devel xmlsec1-openssl xmlsec1-openssl-devel openssl && \
    pip3 install --no-cache-dir --upgrade pip pipenv && \
    pipenv lock --requirements > requirements.txt && \
    pip install --no-cache-dir -r requirements.txt && \
    dnf remove -y gcc python3-devel && \
    rm -rf /var/lib/dnf /var/cache/dnf
COPY . /usr/src/app/
CMD ["./run-server.sh"]
