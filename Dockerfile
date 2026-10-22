# Build stage
FROM registry.access.redhat.com/hi/python:3.12-fips-builder@sha256:d329003dbd3390d548e2e04de12f60dfa42d303dac7285c5e8604ed19f6d802d AS builder
USER root
RUN dnf install -y xmlsec1 xmlsec1-openssl openssl && dnf clean all
WORKDIR /usr/src/app
COPY Pipfile.lock .
RUN pip install --no-cache-dir --upgrade pip micropipenv && micropipenv install
COPY . .
USER ${CONTAINER_DEFAULT_USER}

# Runtime stage
FROM registry.access.redhat.com/hi/python:3.12-fips@sha256:0594c8f41e58d8cb047c2794d671cf11bdce0afbd8b74d27b80ccd7ab59d921d

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
