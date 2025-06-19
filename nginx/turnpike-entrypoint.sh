#!/bin/sh

if ! python3 /etc/nginx/configuration_builder/build_config.py "${BACKENDS_CONFIG_MAP}"
then
    exit 1
fi

exec "$@"
