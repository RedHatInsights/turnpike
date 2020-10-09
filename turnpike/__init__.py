import importlib
from logging import StreamHandler, DEBUG
from logging.config import dictConfig
import os

from flask import Flask
from healthcheck import HealthCheck
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix

from . import plugin, views


class DebugOnlyStreamHandler(StreamHandler):
    def emit(self, record):
        if not record.levelno == DEBUG:
            return
        super().emit(record)


def create_app(test_config=None):
    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": True,
            "formatters": {"default": {"()": "ecs_logging.StdlibFormatter"}},
            "handlers": {
                "debug": {"class": "turnpike.DebugOnlyStreamHandler", "level": "DEBUG", "stream": "ext://sys.stdout"},
                "wsgi": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "level": "DEBUG",
                    "stream": "ext://flask.logging.wsgi_errors_stream",
                },
            },
            "loggers": {
                "turnpike": {
                    "level": "DEBUG" if os.environ.get("FLASK_DEBUG") else "INFO",
                    "handlers": ["wsgi", "debug"],
                }
            },
            "root": {"level": "ERROR", "handlers": ["wsgi"]},
        }
    )
    app = Flask(__name__)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    if test_config:
        app.config.from_mapping(test_config)
    else:
        app.config.from_object("turnpike.config")
    app.config.from_envvar("TURNPIKE_CONFIG", silent=True)

    session_obj = Session()
    session_obj.init_app(app)

    health = HealthCheck()
    app.add_url_rule("/_healthcheck/", view_func=health.run)
    app.add_url_rule("/_nginx_config/", view_func=views.nginx_config_data)

    chain_objs = []
    for plugin_name in app.config["PLUGIN_CHAIN"]:
        mod_name, cls_name = plugin_name.rsplit(".", 1)
        mod = importlib.import_module(mod_name)
        cls = getattr(mod, cls_name)
        if not issubclass(cls, plugin.TurnpikePlugin):
            raise ValueError(f"Plugin {plugin_name} does not resolve to a TurnpikePlugin.")
        app.logger.debug(f"Registering plugin: {plugin_name}")
        instance = cls(app)
        instance.register_blueprint()
        chain_objs.append(instance)
    app.config["PLUGIN_CHAIN_OBJS"] = chain_objs

    app.add_url_rule("/auth/", view_func=views.policy_view)
    app.add_url_rule("/api/turnpike/identity/", view_func=views.identity)
    return app
