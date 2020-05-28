FROM nginx

# support running as an arbitrary user which belogs to the root group
RUN chmod g+rwx /var/cache/nginx /var/run /var/log/nginx

COPY . /etc/nginx
