import base64
import json

from flask import current_app, request, make_response

from turnpike.metrics import Metrics
from turnpike.plugin import PolicyContext


def policy_view():
    context = PolicyContext()

    # Start by identifying which route is being asked about
    original_url = request.headers.get("X-Original-Uri", "/")
    nginx_matched_backend = request.headers.get("X-Matched-Backend")

    current_app.logger.debug(f"Received original URI: {original_url}")
    current_app.logger.debug(f"Matched back end in NGINX: {nginx_matched_backend}")

    if nginx_matched_backend:
        context.backend = match_by_backend_name(nginx_matched_backend)
    else:
        context.backend = match_by_route(original_url)

    if not context.backend:
        # This condition shouldn't be hit - it would mean that there was a
        # bug, a mismatch between the routes configured in nginx and the
        # routes configured here.
        status_code = 403
        current_app.logger.warning(f"Policy inquiry about unconfigured route! {original_url}")
        Metrics.request_count.labels(original_url, status_code).inc()
        return make_response("", status_code)

    current_app.logger.debug(f"Matched back end in Turnpike: {context.backend['name']}")

    for plugin in current_app.config.get("PLUGIN_CHAIN_OBJS", []):
        current_app.logger.debug(f"Processing request with plugin {plugin}.")
        context = plugin.process(context)
        if context.status_code:
            current_app.logger.debug(f"Plugin set status code {context.status_code}.")
            Metrics.request_count.labels(context.backend["name"], context.status_code).inc()
            return make_response("", context.status_code, context.headers)
    Metrics.request_count.labels(context.backend["name"], current_app.config["DEFAULT_RESPONSE_CODE"]).inc()
    return make_response("", current_app.config["DEFAULT_RESPONSE_CODE"], context.headers)


def identity():
    if request.headers.get("X-Rh-Identity"):
        try:
            response = json.loads(base64.decodebytes(request.headers["X-Rh-Identity"].encode("utf8")))
        except Exception as e:
            response = {"error": f"Error decoding identity header: {e}"}
    else:
        response = {"error": "No x-rh-identity header found in the request."}
    return make_response(response, 200)


def nginx_config_data():
    to_upstream = set()
    to_policy_service = set()
    for plugin in current_app.config.get("PLUGIN_CHAIN_OBJS", []):
        to_upstream = to_upstream.union(plugin.headers_to_forward)
        to_policy_service = to_policy_service.union(plugin.headers_needed)
    response_dict = dict(
        to_upstream=list(to_upstream),
        to_policy_service=list(to_policy_service),
        blueprints=[bp.url_prefix for bp in current_app.blueprints.values()],
    )
    return make_response(json.dumps(response_dict), 200, {"Content-Type": "application/json"})


def session():
    session_id = request.cookies.get("session")
    if session_id:
        response = {"session": session_id}
    else:
        response = {"error": "No session cookie found in the request."}
    return make_response(response, 200)


def match_by_backend_name(nginx_matched_backend):
    """Returns the back end that matches the given name."""

    for backend in current_app.config["BACKENDS"]:
        if backend["name"] == nginx_matched_backend:
            return backend

    return None


def match_by_route(original_url):
    """Returns the back end that matches the backend whose route matches the closest to the given one."""

    matches = [backend for backend in current_app.config["BACKENDS"] if original_url.startswith(backend["route"])]

    if matches:
        return max(matches, key=lambda match: len(match["route"]))
    else:
        return None
