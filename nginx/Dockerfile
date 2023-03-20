FROM registry.access.redhat.com/ubi8-minimal

# support running as an arbitrary user which belongs to the root group
RUN microdnf module enable nginx:1.20 && \
    microdnf install -y nginx python38-jinja2 python38-yaml python38 && \
    chmod g+rwx /var/log/nginx && \
    rm -rf /var/lib/dnf /var/cache/dnf

COPY . /etc/nginx
RUN chgrp -R root /etc/nginx && chmod -R g+rwX /etc/nginx
COPY turnpike-entrypoint.sh /turnpike-entrypoint.sh
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml
ENTRYPOINT ["/turnpike-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
