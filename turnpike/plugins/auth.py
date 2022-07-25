import importlib
import time

from flask import request, current_app, g

from ..plugin import TurnpikePlugin, TurnpikeAuthPlugin
from ..metrics import AuthMetrics


class AuthPlugin(TurnpikePlugin):
    def __init__(self, app):
        super().__init__(app)
        self.auth_plugins = []
        for plugin_name in self.app.config["AUTH_PLUGIN_CHAIN"]:
            mod_name, cls_name = plugin_name.rsplit(".", 1)
            mod = importlib.import_module(mod_name)
            cls = getattr(mod, cls_name)
            if not issubclass(cls, TurnpikeAuthPlugin):
                raise ValueError(f"Auth plugin {plugin_name} is not a TurnpikeAuthPlugin.")
            plugin_instance = cls(app)
            self.auth_plugins.append(plugin_instance)
            self.headers_to_forward = self.headers_to_forward.union(plugin_instance.headers_to_forward)
            self.headers_needed = self.headers_needed.union(plugin_instance.headers_needed)

        @app.before_request
        def before_request():
            g.start = time.time()

        @app.after_request
        def after_request(response):
            diff = (time.time() - g.start) * 1000
            current_app.logger.debug(f"Response {response.__dict__} in time: {diff}ms")
            AuthMetrics.auth_request_latency.observe(diff)
            return response


    def register_blueprint(self):
        for plugin_instance in self.auth_plugins:
            plugin_instance.register_blueprint()

    def process(self, context):
        current_app.logger.debug("Begin auth")
        backend_auth = context.backend.get("auth")

        # If the route does not require authentication, then we defer to other
        # plugins.
        if not backend_auth:
            current_app.logger.debug("No auth required for backend")
            return context
        for auth_plugin in self.auth_plugins:
            context = auth_plugin.process(context, backend_auth)
            if context.auth or context.status_code:
                # The auth plugin authenticated the user or wants to return immediately
                current_app.logger.debug(f"Auth complete: {context}")
                return context

        # If we get here, no plugin reported successful authentication.
        context.status_code = 401
        context.headers["login_url"] = next(
            url for url in [plugin.login_url() for plugin in self.auth_plugins] if url is not None
        )
        return context
