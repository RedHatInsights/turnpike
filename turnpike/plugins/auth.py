import importlib
from http import HTTPStatus

from flask import current_app

from ..plugin import TurnpikePlugin, TurnpikeAuthPlugin, PolicyContext


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

    def process(self, context: PolicyContext) -> PolicyContext:
        current_app.logger.debug("Begin auth")
        backend = context.backend

        # If the route does not require authentication, then we defer to other
        # plugins.
        if not backend.requires_authentication():
            current_app.logger.debug("No auth required for backend")
            return context
        for auth_plugin in self.auth_plugins:
            context = auth_plugin.process(context=context, backend_auth=backend)
            if context.auth or context.status_code:
                # The auth plugin authenticated the user or wants to return immediately
                current_app.logger.debug(f"Auth complete: {context}")
                return context

        # If we get here, no plugin reported successful authentication.
        context.status_code = HTTPStatus.UNAUTHORIZED

        return context
