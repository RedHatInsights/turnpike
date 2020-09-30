#!/bin/sh

python3 /etc/nginx/build_config.py $BACKENDS_CONFIG_MAP
exec "$@"
