#!/bin/sh

python3 /etc/nginx/build-backends.py $BACKENDS_CONFIG_MAP /etc/nginx/api_conf.d
