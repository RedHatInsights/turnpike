#!/usr/bin/env python3

import argparse
import os
import warnings

import jinja2
import yaml
import yaml.error


# Do not include leading or trailing slashes in these routes
FORBIDDEN_ROUTES = ["", "saml", "auth"]


def main(args):
    try:
        with open(args.config_map_path) as ifs:
            backends = yaml.safe_load(ifs)
    except OSError:
        raise Exception(f"Error opening config map at {args.config_map_path}")
    except yaml.error.YAMLError as e:
        raise Exception(f"Error parsing config map as YAML: {e}")

    assert isinstance(backends, list), "YAML file does not contain a list of backends."

    with open("/etc/nginx/backend_template.conf.j2") as ifs:
        template = jinja2.Template(ifs.read())
    for backend in backends:
        name = backend["name"]
        print(f"Processing backend configuration for {name}")
        route = backend["route"]
        if route.strip("/") in FORBIDDEN_ROUTES:
            warnings.warn(f"Forbidden route found in config map: {route} - skipping.")

        with open(os.path.join(args.nginx_confd_dir, f"{name}.conf"), "w") as ofs:
            ofs.write(template.render(**backend))
    print("Done.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Build nginx backend configurations from config map")
    parser.add_argument("config_map_path", help="Path to the config map with routes")
    parser.add_argument("nginx_confd_dir", help="Path to output nginx conf.d files")

    args = parser.parse_args()
    main(args)
