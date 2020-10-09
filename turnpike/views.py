import base64
import json
import datetime

from flask import current_app, request, make_response
from pytz import utc

from .plugin import PolicyContext


STATUS_CODE_OUTCOMES = {200: "success", 401: "unknown", 403: "failure"}


def log_and_respond(context, content, start_time, status_code=None):
    extra = context.log_data
    status_code = status_code or context.status_code or current_app.config["DEFAULT_RESPONSE_CODE"]
    end_time = datetime.datetime.utcnow().replace(tzinfo=utc)
    extra.update(
        {
            "event.action": "policy-check",
            "event.outcome": STATUS_CODE_OUTCOMES[status_code],
            "event.start": start_time.isoformat(),
            "event.end": end_time.isoformat(),
            "event.duration": int((end_time - start_time).total_seconds() / 1e-9),
            "event.reason": context.result.strip(),
        }
    )
    current_app.logger.info(content, extra=extra)
    return make_response(content, status_code, context.headers)


def policy_view():
    start_time = datetime.datetime.utcnow().replace(tzinfo=utc)
    context = PolicyContext()

    # Start by identifying which route is being asked about
    original_url = request.headers.get("X-Original-Uri", "/")
    matches = [backend for backend in current_app.config["BACKENDS"] if original_url.startswith(backend["route"])]
    if not matches:
        # This condition shouldn't be hit - it would mean that there was a
        # bug, a mismatch between the routes configured in nginx and the
        # routes configured here.
        return log_and_respond(context, f"Policy inquiry about unconfigured route! {original_url}", start_time, 403)
    context.backend = max(matches, key=lambda match: len(match["route"]))
    context.log_data["rule.ruleset"] = context.backend["name"]

    for plugin in current_app.config.get("PLUGIN_CHAIN_OBJS", []):
        current_app.logger.debug(f"Processing request with plugin {plugin}.")
        context = plugin.process(context)
        if context.status_code:
            break
    return log_and_respond(context, "", start_time)


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
