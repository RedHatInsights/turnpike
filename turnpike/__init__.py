import importlib
from logging.config import dictConfig

from flask import Flask
from healthcheck import HealthCheck
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix

from . import plugin, views


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
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    if test_config:
        app.config.from_mapping(test_config)
    else:
        app.config.from_object("turnpike.config")
    app.config.from_envvar("TURNPIKE_CONFIG")

    session_obj = Session()
    session_obj.init_app(app)

    health = HealthCheck()
    app.add_url_rule("/_healthcheck/", view_func=health.run)

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
    return app
