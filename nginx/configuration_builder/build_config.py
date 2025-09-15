#!/usr/bin/env python3

import argparse
import json
import logging
import os
import re
import sys
import time
import typing
from urllib import parse, request, error

import jinja2
import yaml
import yaml.error


# Do not include leading or trailing slashes in these routes
PROTECTED_ROUTES = ["saml", "auth", "_nginx"]
ALLOWED_ROUTES = json.loads(os.environ.get("TURNPIKE_ALLOWED_ROUTES", '["public", "api", "app"]'))
ALLOWED_NO_AUTH_ROUTES = json.loads(os.environ.get("TURNPIKE_NO_AUTH_ROUTES", '["public"]'))
ALLOWED_ORIGIN_DOMAINS = json.loads(os.environ.get("TURNPIKE_ALLOWED_ORIGIN_DOMAINS", '[".svc.cluster.local"]'))

# Configure the logging.
logging_handle = "logger-nginx-build-config"
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(logging_handle)


class InvalidBackendDefinitionError(Exception):
    """Exception that gets raised when a backend has been improperly defined"""

    pass


def validate_route(backend):
    name: str = backend["name"]
    route: str = backend["route"]
    # The route must be a valid path
    if not (route.startswith("/") and parse.urlparse(route).path == route):
        raise InvalidBackendDefinitionError(
            f"[backend_name: {name}][route: {route}] The back end's route is not a valid URL path"
        )

    # The origin must be a URL in a trusted domain
    origin_hostname: str = parse.urlparse(backend["origin"]).netloc.split(":", 1)[0]
    if not any([origin_hostname.endswith(allowed_domain) for allowed_domain in ALLOWED_ORIGIN_DOMAINS]):
        raise InvalidBackendDefinitionError(
            f'[backend_name: {name}][origin: {backend["origin"]}] The back end\'s route\'s origin is in an untrusted domain'
        )

    first_path_segment: str = route.strip("/").split("/", 1)[0]
    # Routes Turnpike needs to function are off limits
    if first_path_segment in PROTECTED_ROUTES:
        raise InvalidBackendDefinitionError(
            f"[backend_name: {name}][route: {route}] The back end's route is a protected route"
        )

    # Routes must be in an allowed section of URL-space or begin with an underscore
    if not (first_path_segment in ALLOWED_ROUTES or first_path_segment.startswith("_")):
        raise InvalidBackendDefinitionError(
            f"[backend_name: {name}][route: {route}] The back end's route is not part of the allowed routes"
        )

    # Routes must have some sort of restriction like an "auth" block or a "source_ip" block. In the case that they do
    # not have those elements, the first segment of the path must always begin with the allowed "public" segments that
    # we have configured.
    if ("auth" not in backend and "source_ip" not in backend) and (first_path_segment not in ALLOWED_NO_AUTH_ROUTES):
        raise InvalidBackendDefinitionError(
            f'[backend_name: {name}] The back end does not have either an "auth" or "source_ip" definitions, nor its route\'s first segment begins with the allowed public segments. Either add an access restriction mechanism, or modify the route so that it begins with one of the allowed public segments'
        )


def get_resolver():
    resolver_file_name = "/etc/resolv.conf"
    file = open(resolver_file_name, "r")
    match = re.search("(?<=nameserver )(.*)(?=\\n)", file.read())
    if not match:
        raise Exception(f"Error getting resolver from {resolver_file_name}")

    resolver = match.group()
    print(f"Using resolver: {resolver}")
    return resolver


def main(args):
    try:
        with open(args.config_map_path) as ifs:
            backends = yaml.safe_load(ifs)
    except OSError:
        raise Exception(f"Error opening config map at {args.config_map_path}")
    except yaml.error.YAMLError as e:
        raise Exception(f"Error parsing config map as YAML: {e}")

    assert isinstance(backends, list), "YAML file does not contain a list of backends."

    with open("/etc/nginx/configuration_builder/templates/api_gateway.conf.j2") as ifs:
        template = jinja2.Template(ifs.read())

    with open("/etc/nginx/api_gateway.conf", "w") as ofs:
        ofs.write(template.render(**os.environ))

    write_nginx_locations(backends)


def write_nginx_locations(backends) -> None:
    """Write the locations Nginx will use from the given back ends."""
    # The DNS resolver to use in the Nginx locations.
    resolver = get_resolver()

    # Open the Nginx location template.
    with open("/etc/nginx/configuration_builder/templates/nginx_location_template.conf.j2") as ifs:
        template = jinja2.Template(ifs.read())

    for backend in backends:
        backend_name = backend["name"]

        # Validate the back end's definition.
        validate_route(backend)

        location_path = f"/etc/nginx/api_conf.d/{backend_name}.conf"
        with open(location_path, "w") as ofs:
            ofs.write(template.render(resolver=resolver, **backend))

        logger.info(f"[backend_name: {backend_name}] Nginx location created in {location_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build nginx backend configurations from config map")
    parser.add_argument("config_map_path", help="Path to the config map with routes")

    args = parser.parse_args()

    try:
        main(args)
    except InvalidBackendDefinitionError as e:
        logger.error(e)
        sys.exit(1)
