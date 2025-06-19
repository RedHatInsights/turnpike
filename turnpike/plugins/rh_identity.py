import base64
import json

from flask import current_app

from ..plugin import TurnpikePlugin


class RHIdentityPlugin(TurnpikePlugin):
    def process(self, context):
        if context.auth:
            identity_type = context.auth["auth_plugin"].principal_type
            auth_type = context.auth["auth_plugin"].name
            auth_data = context.auth["auth_data"]
            header_data = dict(
                identity=dict(
                    type=identity_type,
                    auth_type=auth_type,
                    **{identity_type.lower(): auth_data},
                )
            )
            current_app.logger.debug(f"Identity header content: {header_data}")
            context.headers["X-RH-Identity"] = (
                base64.encodebytes(json.dumps(header_data).encode("utf8")).decode("utf-8").replace("\n", "")
            )
        return context
