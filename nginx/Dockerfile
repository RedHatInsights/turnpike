FROM registry.access.redhat.com/hi/core-runtime:2.43-openssl-fips-builder

USER root

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

# support running as an arbitrary user which belongs to the root group
RUN microdnf install -y nginx python3.12 pip && \
    pip3 install --no-cache-dir jinja2 pyyaml && \
    chmod g+rwx /var/log/nginx && \
    rm -rf /var/lib/dnf /var/cache/dnf

COPY . /etc/nginx
RUN chgrp -R root /etc/nginx && chmod -R g+rwX /etc/nginx
COPY turnpike-entrypoint.sh /turnpike-entrypoint.sh

USER ${CONTAINER_DEFAULT_USER}

ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml
ENTRYPOINT ["/turnpike-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
