# Build stage
FROM registry.access.redhat.com/hi/python:3.11-fips-builder AS builder
USER root
RUN dnf install -y xmlsec1 xmlsec1-openssl openssl && dnf clean all
WORKDIR /usr/src/app
COPY Pipfile.lock .
RUN pip install --no-cache-dir --upgrade pip micropipenv && micropipenv install
COPY . .
USER ${CONTAINER_DEFAULT_USER}

# Runtime stage
FROM registry.access.redhat.com/hi/python:3.11-fips-builder

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

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/src/app /usr/src/app

CMD ["/bin/sh", "./run-server.sh"]
