# Build stage
FROM registry.access.redhat.com/hi/python:3.12-fips-builder@sha256:f7a2d017eab9c9cdbe0cff9da3a5b51f7ef1ec9b1eae41eff5d1dc685d3ea76a AS builder
USER root
RUN dnf install -y xmlsec1 xmlsec1-openssl openssl && dnf clean all
WORKDIR /usr/src/app
COPY Pipfile.lock .
RUN pip install --no-cache-dir --upgrade pip micropipenv && micropipenv install
COPY . .
USER ${CONTAINER_DEFAULT_USER}

# Runtime stage
FROM registry.access.redhat.com/hi/python:3.12-fips@sha256:1328d1a0c3e93fe99457521f2ec09df54b0e13c79ba3ea238e98e998aa7c1942

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

COPY --from=builder /usr/local/lib64/python3.12/site-packages /usr/local/lib64/python3.12/site-packages
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /usr/local/sbin /usr/local/sbin
COPY --from=builder /usr/src/app /usr/src/app

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "turnpike:create_app()"]
