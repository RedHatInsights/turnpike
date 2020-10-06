#!/usr/bin/env python3

import argparse
import json
import os
import time
from urllib import parse, request, error
import warnings

import jinja2
import yaml
import yaml.error


# Do not include leading or trailing slashes in these routes
PROTECTED_ROUTES = ["saml", "auth", "_nginx"]
ALLOWED_ROUTES = json.loads(os.environ.get("TURNPIKE_ALLOWED_ROUTES", '["public", "api", "app"]'))
ALLOWED_NO_AUTH_ROUTES = json.loads(os.environ.get("TURNPIKE_NO_AUTH_ROUTES", '["public"]'))
ALLOWED_ORIGIN_DOMAINS = json.loads(os.environ.get("TURNPIKE_ALLOWED_ORIGIN_DOMAINS", '[".svc.cluster.local"]'))


def validate_route(backend):
    name = backend["name"]
    route = backend["route"]
    # The route must be a valid path
    if not (route.startswith("/") and parse.urlparse(route).path == route):
        warnings.warn(f"Routes must be valid URL paths: {route} - skipping {name}.")
        return False
    # The origin must be a URL in a trusted domain
    origin_hostname = parse.urlparse(backend["origin"]).netloc.split(":", 1)[0]
    if not any([origin_hostname.endswith(allowed_domain) for allowed_domain in ALLOWED_ORIGIN_DOMAINS]):
        warnings.warn(f"Route origin is in an untrusted domain: {origin_hostname} - skipping {name}.")
        return False
    first_path_segment = route.strip("/").split("/", 1)[0]
    # Routes Turnpike needs to function are off limits
    if first_path_segment in PROTECTED_ROUTES:
        warnings.warn(f"Protected route found in config map: {route} - skipping {name}.")
        return False
    # Routes must be in an allowed section of URL-space or begin with an underscore
    if not (first_path_segment in ALLOWED_ROUTES or first_path_segment.startswith("_")):
        warnings.warn(f"Route found outside of allowed prefixes: {route} - skipping {name}.")
        return False
    # Routes must have authentication required unless they're in an allowed section of URL-space
    if not (first_path_segment in ALLOWED_NO_AUTH_ROUTES or "auth" in backend):
        warnings.warn(f"Route not in public area of URL space but did not require auth: {route} - skipping {name}")
        return False
    return True


def main(args):
    try:
        with open(args.config_map_path) as ifs:
            backends = yaml.safe_load(ifs)
    except OSError:
        raise Exception(f"Error opening config map at {args.config_map_path}")
    except yaml.error.YAMLError as e:
        raise Exception(f"Error parsing config map as YAML: {e}")

    assert isinstance(backends, list), "YAML file does not contain a list of backends."

    response_obj = None
    request_obj = request.Request(
        f'{os.environ["FLASK_SERVICE_URL"]}/_nginx_config/',
        headers={
            "X-Forwarded-Host": os.environ["FLASK_SERVER_NAME"],
            "X-Forwarded-Port": "443",
            "X-Forwarded-Proto": "https",
        },
    )
    while not response_obj:
        try:
            response_obj = request.urlopen(request_obj)
        except error.URLError:
            print("Could not contact Flask. Assuming it is still starting up. Sleeping 3 seconds.")
            time.sleep(3)
    nginx_config = json.load(response_obj)
    headers_to_upstream = nginx_config["to_upstream"]
    headers_to_policy_service = nginx_config["to_policy_service"]
    blueprints = nginx_config["blueprints"]

    with open("/etc/nginx/api_gateway.conf.j2") as ifs:
        template = jinja2.Template(ifs.read())
    with open("/etc/nginx/api_gateway.conf", "w") as ofs:
        ofs.write(template.render(headers=headers_to_policy_service, blueprints=blueprints, **os.environ))

    with open("/etc/nginx/backend_template.conf.j2") as ifs:
        template = jinja2.Template(ifs.read())
    for backend in backends:
        name = backend["name"]
        print(f"Processing backend configuration for {name}")
        if validate_route(backend):
            with open(f"/etc/nginx/api_conf.d/{name}.conf", "w") as ofs:
                ofs.write(template.render(headers=headers_to_upstream, **backend))
    print("Done.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build nginx backend configurations from config map")
    parser.add_argument("config_map_path", help="Path to the config map with routes")

    args = parser.parse_args()
    main(args)
