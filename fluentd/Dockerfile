# fluentd/Dockerfile

FROM fluent/fluentd:v1.12.0-debian-1.0
USER root
RUN export FLUENT_UID=0
RUN ["gem", "install", "fluent-plugin-prometheus"]
USER fluent