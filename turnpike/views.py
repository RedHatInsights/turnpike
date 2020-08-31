import base64
import json
import logging

from flask import current_app, request, make_response


logger = logging.getLogger(__name__)


class PolicyContext:
    auth = None
    headers = {}
    status_code = None
    data = {}

    def __str__(self):
        return f"PolicyContext: auth={self.auth}, headers={self.headers}, status_code={self.status_code}"


def policy_view():
    context = PolicyContext()
    for plugin in current_app.config.get("PLUGIN_CHAIN_OBJS", []):
        logger.debug(f"Processing request with plugin {plugin}.")
        context = plugin.process(context)
        if context.status_code:
            logger.debug(f"Plugin set status code {context.status_code}.")
            return make_response("", context.status_code, context.headers)
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
