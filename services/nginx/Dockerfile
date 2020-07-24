FROM nginx

# support running as an arbitrary user which belogs to the root group
RUN chmod g+rwx /var/cache/nginx /var/run /var/log/nginx && \
    apt-get update && \
    apt-get install --no-install-recommends --no-install-suggests -y python3-jinja2 python3-yaml python3-minimal && \
    apt-get remove --purge --auto-remove -y && rm -rf /var/lib/apt/lists/*

COPY . /etc/nginx
RUN chmod g+rwx /etc/nginx/api_conf.d
COPY turnpike-entrypoint.sh /docker-entrypoint.d/turnpike-entrypoint.sh
ENV BACKENDS_CONFIG_MAP=/etc/turnpike/backends.yml
