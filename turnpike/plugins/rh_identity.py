import base64
import json
import logging

from ..plugin import TurnpikePlugin


logger = logging.getLogger(__name__)


class RHIdentityPlugin(TurnpikePlugin):
    def process(self, context):
        if context.auth:
            identity_type = context.auth["auth_plugin"].principal_type
            auth_type = context.auth["auth_plugin"].name
            auth_data = context.auth["auth_data"]
            header_data = dict(
                identity=dict(type=identity_type, auth_type=auth_type, **{identity_type.lower(): auth_data})
            )
            logger.debug(f"Identity header content: {header_data}")
            context.headers["X-RH-Identity"] = base64.encodebytes(json.dumps(header_data).encode("utf8")).replace(
                b"\n", b""
            )
        return context
