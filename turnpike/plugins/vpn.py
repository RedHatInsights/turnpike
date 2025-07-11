import logging
import re

from http import HTTPStatus
from flask import request

from ..plugin import TurnpikePlugin, PolicyContext


class VPNPlugin(TurnpikePlugin):
    vpn_pattern = r"(?:mtls\.)?private\.(?:console|cloud)\.(?:(stage|dev)\.)?redhat\.com"
    edge_host_header = "x-rh-edge-host"
    nginx_original_request_comes_from_vpn = "X-Rh-Original-Request-Comes-From-Vpn"
    vpn_config_key = "private"

    def __init__(self, app):
        self.vpn_regex = re.compile(self.vpn_pattern)
        self.env = app.config.get("WEB_ENV").casefold()
        self.headers_needed = set(self.edge_host_header)

        super().__init__(app)

    def process(self, context: PolicyContext):
        if self.vpn_config_key not in context.backend or context.backend[self.vpn_config_key] != True:  # type: ignore
            return context

        edge_host = request.headers.get(self.edge_host_header)
        backend_name = context.backend["name"]

        if not edge_host:
            # TODO: integrate glitchtip with turnpike and capture this so we get alert if it happens, see https://issues.redhat.com/browse/RHCLOUD-40788
            return self.forbidden(
                context,
                logging.WARNING,
                "request to backend '%s' denied - missing '%s' header which is required for vpn restricted backend",
                backend_name,
                self.edge_host_header,
            )

        match = self.vpn_regex.fullmatch(edge_host)

        if not match:
            return self.forbidden(
                context,
                logging.DEBUG,
                "request to backend '%s' denied - '%s':'%s' does not originate from vpn restricted edge host",
                backend_name,
                self.edge_host_header,
                edge_host,
            )

        match_env = match.groups()[0]
        if self.is_production() and match_env:
            return self.forbidden(
                context,
                logging.INFO,
                "request to backend '%s' denied - '%s':'%s' is from edge host in wrong env, expected prod host",
                backend_name,
                self.edge_host_header,
                edge_host,
            )
        elif not self.is_production() and not match_env:
            return self.forbidden(
                context,
                logging.INFO,
                "request to backend '%s' denied - '%s':'%s' is from edge host in wrong env, expected non prod host",
                backend_name,
                self.edge_host_header,
                edge_host,
            )

        # Set up a header for Nginx so that it can redirect the requester to
        # the internal VPN's host whenever it is necessary.
        context.headers[self.nginx_original_request_comes_from_vpn] = "true"

        self.app.logger.debug(
            "request to backend '%s' approved - '%s':'%s' is valid for vpn restricted backend",
            backend_name,
            self.edge_host_header,
            edge_host,
        )
        return context

    def forbidden(self, context, level, msg, *args, **kwargs):
        self.app.logger.log(level, msg, *args, **kwargs)
        context.status_code = HTTPStatus.FORBIDDEN
        return context

    def is_production(self):
        return self.env == "prod" or self.env == "production"
