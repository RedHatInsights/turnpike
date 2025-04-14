FROM registry.access.redhat.com/ubi9/ubi-minimal:9.5-1742914212

# support running as an arbitrary user which belongs to the root group
RUN microdnf module enable -y nginx:1.24 && \
    microdnf install -y nginx python3.11 pip && \
    pip3 install --no-cache-dir jinja2 pyyaml && \
    chmod g+rwx /var/log/nginx && \
    rm -rf /var/lib/dnf /var/cache/dnf

COPY . /etc/nginx
RUN chgrp -R root /etc/nginx && chmod -R g+rwX /etc/nginx
RUN ls /etc/nginx/turnpike
COPY /etc/nginx/nginx/turnpike-entrypoint.sh /turnpike-entrypoint.sh
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml
ENTRYPOINT ["/turnpike-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
