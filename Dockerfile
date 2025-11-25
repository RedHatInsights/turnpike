FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7-1763362218

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
