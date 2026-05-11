FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7-1778072020

LABEL name="turnpike" \
      summary="Red Hat Insights Turnpike Authentication Gateway" \
      description="Authentication and authorization gateway for Red Hat Insights platform using Nginx auth_request and Flask policy service. Supports SAML SSO, mTLS, and OIDC authentication with extensible plugin architecture." \
      io.k8s.description="Authentication and authorization gateway for Red Hat Insights platform using Nginx auth_request and Flask policy service. Supports SAML SSO, mTLS, and OIDC authentication with extensible plugin architecture." \
      io.k8s.display-name="Red Hat Insights Turnpike" \
      io.openshift.tags="insights,turnpike,auth,gateway,authentication,authorization" \
      com.redhat.component="turnpike" \
      version="1.0" \
      release="1" \
      vendor="Red Hat, Inc." \
      url="https://github.com/RedHatInsights/turnpike" \
      distribution-scope="private" \
      maintainer="platform-accessmanagement@redhat.com"

ENV FLASK_RUN_HOST=0.0.0.0
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml

WORKDIR /usr/src/app

COPY Pipfile.lock /usr/src/app/

RUN microdnf install --nodocs -y gcc xmlsec1 python3.11 python3.11-pip python3.11-devel xmlsec1-openssl openssl tar

RUN python3.11 -m pip install --upgrade pip && \
    python3.11 -m pip install micropipenv && \
    python3.11 -m micropipenv install && \
    microdnf remove -y gcc

# TODO: Remove once base image includes Go 1.25.10
ENV GO_VERSION=1.25.10
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

COPY . /usr/src/app/

CMD ["./run-server.sh"]
