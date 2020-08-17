#!/bin/sh

export VAR='$'
envsubst < /etc/nginx/api_gateway.conf.tmpl > /etc/nginx/api_gateway.conf
python3 /etc/nginx/build-backends.py $BACKENDS_CONFIG_MAP /etc/nginx/api_conf.d
