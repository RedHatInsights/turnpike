import importlib
from logging.config import dictConfig

from flask import Flask
from flask_session import Session
from healthcheck import HealthCheck
from prometheus_client import make_wsgi_app
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.middleware.proxy_fix import ProxyFix

from . import plugin, views
from .cache import cache


def create_app(test_config=None):
    dictConfig(
        {
            "version": 1,
            "formatters": {
                "default": {"format": "{levelname} {asctime} {module} {process:d} {thread:d} {message}", "style": "{"}
            },
            "handlers": {
                "wsgi": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "level": "DEBUG",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                }
            },
            "root": {"level": "DEBUG", "handlers": ["wsgi"]},
        }
    )

    if test_config:
        # Sometimes we need unique application names when asserting which logs have been written. Having the same
        # application name makes the log assertions to not work.
        app_name = test_config.get("APP_NAME")
        if app_name:
            app = Flask(app_name)
        else:
            app = Flask(__name__)

        app.config.from_mapping(test_config)
        cache.init_app(app, config=app.config)
    else:
        app = Flask(__name__)
        app.config.from_object("turnpike.config")
        cache.init_app(app, config=app.config)
        session_obj = Session()
        session_obj.init_app(app)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    app.config.from_envvar("TURNPIKE_CONFIG", silent=True)

    # Validate that the OIDC back ends are properly defined.
    validate_oidc_definitions(app)

    health = HealthCheck()
    app.add_url_rule("/_healthcheck/", view_func=health.run)
    app.add_url_rule("/_nginx_config/", view_func=views.nginx_config_data)
    app.wsgi_app = DispatcherMiddleware(app.wsgi_app, {"/metrics": make_wsgi_app()})

    chain_objs = []
    for plugin_name in app.config["PLUGIN_CHAIN"]:
        mod_name, cls_name = plugin_name.rsplit(".", 1)
        mod = importlib.import_module(mod_name)
        cls = getattr(mod, cls_name)
        if not issubclass(cls, plugin.TurnpikePlugin):
            raise ValueError(f"Plugin {plugin_name} does not resolve to a TurnpikePlugin.")
        app.logger.info(f"Registering plugin: {plugin_name}")
        instance = cls(app)
        instance.register_blueprint()
        chain_objs.append(instance)
    app.config["PLUGIN_CHAIN_OBJS"] = chain_objs

    app.add_url_rule("/auth/", view_func=views.policy_view)
    app.add_url_rule("/api/turnpike/identity/", view_func=views.identity)
    app.add_url_rule("/api/turnpike/session/", view_func=views.session)
    return app


def validate_oidc_definitions(app: Flask):
    """Validates that the OIDC back ends are correctly defined."""
    backends = app.config.get("BACKENDS")
    if not backends:
        raise NotImplementedError("No backends have been configured in the application")

    for backend in backends:
        auth = backend.get("auth")
        if not auth:
            app.logger.warning(f'The backend "{backend["name"]}" does not contain an "auth" object')
            continue

        if not "oidc" in auth:
            continue

        oidc = auth.get("oidc")
        if not oidc:
            raise NotImplementedError(
                f'The backend "{backend["name"]}" contains an empty "oidc" object. Either add some service accounts or delete it.'
            )

        service_accounts = oidc.get("serviceAccounts")
        if not service_accounts:
            raise NotImplementedError(
                f'The backend "{backend["name"]}" has a "serviceAccounts" definition but the list is empty'
            )

        for service_account in service_accounts:
            if "clientId" not in service_account:
                raise NotImplementedError(
                    f'The backend "{backend["name"]}" has a "service account" defined with a missing "clientId" property'
                )

            if not service_account.get("clientId"):
                raise NotImplementedError(
                    f'The backend "{backend["name"]}" has a "service account" defined with an empty "clientId" property'
                )

            if "scopes" in service_account:
                scopes = service_account.get("scopes")
                if not scopes:
                    raise NotImplementedError(
                        f'The backend "{backend["name"]}" has a "service account" defined with an empty "scopes" property. Either add some scopes or delete the "scopes" definition.'
                    )

                for scope in scopes:
                    if not scope:
                        raise NotImplementedError(
                            f'The backend "{backend["name"]}" has a "service account" defined with a list that has an empty scope.'
                        )
