FROM registry.access.redhat.com/ubi9/ubi-minimal:9.7-1764794109

LABEL name="turnpike-nginx" \
      summary="Red Hat Insights Turnpike Nginx Proxy" \
      description="Nginx reverse proxy component for Turnpike authentication gateway. Routes requests and delegates authentication to Flask policy service via auth_request." \
      io.k8s.description="Nginx reverse proxy component for Turnpike authentication gateway. Routes requests and delegates authentication to Flask policy service via auth_request." \
      io.k8s.display-name="Red Hat Insights Turnpike Nginx" \
      io.openshift.tags="insights,turnpike,nginx,proxy,gateway" \
      com.redhat.component="turnpike-nginx" \
      version="1.0" \
      release="1" \
      vendor="Red Hat, Inc." \
      url="https://github.com/RedHatInsights/turnpike" \
      distribution-scope="private" \
      maintainer="platform-accessmanagement@redhat.com"

# Install Go 1.25.5 to address CVE-2025-61729, CVE-2025-61727 & CVE-2025-4598 (Until new ubi9 minimal image supports this go version)
RUN curl -LO https://go.dev/dl/go1.25.5.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf go1.25.5.linux-amd64.tar.gz && \
    rm go1.25.5.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# support running as an arbitrary user which belongs to the root group
RUN microdnf module enable -y nginx:1.24 && \
    microdnf install -y nginx python3.11 pip && \
    pip3 install --no-cache-dir jinja2 pyyaml && \
    chmod g+rwx /var/log/nginx && \
    rm -rf /var/lib/dnf /var/cache/dnf

COPY . /etc/nginx
RUN chgrp -R root /etc/nginx && chmod -R g+rwX /etc/nginx
COPY turnpike-entrypoint.sh /turnpike-entrypoint.sh
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml
ENTRYPOINT ["/turnpike-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
