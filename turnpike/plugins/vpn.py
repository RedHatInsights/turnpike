from http import HTTPStatus

from flask import request, Flask
from requests.exceptions import InvalidHeader

from .common.AllowedNetworks import AllowedNetworks
from .common.header_validator import HeaderValidator
from ..plugin import TurnpikePlugin, PolicyContext


class VPNPlugin(TurnpikePlugin):
    nginx_original_request_comes_from_vpn = "X-Rh-Original-Request-Comes-From-Vpn"
    vpn_config_key = "private"

    def __init__(self, app: Flask):
        self.env = app.config.get("WEB_ENV").casefold()
        self.header_validator = HeaderValidator(app)

        super().__init__(app)

    def process(self, context: PolicyContext):
        if not context.backend:
            self.app.logger.info(f"Skipping VPN plugin because the context does not have a back end: {context}")
            return context

        edge_host = request.headers.get(HeaderValidator.EDGE_HOST_HEADER)
        backend_name = context.backend["name"]

        # Determine whether the backend is VPN-restricted or not.
        vpn_edge_host_header_required: bool = (self.vpn_config_key in context.backend) and (
            context.backend.get(self.vpn_config_key) == True
        )

        # When the "edge host" header is not present for VPN-restricted back
        # ends, the request needs to be rejected.
        #
        # Otherwise, it is safe to skip the VPN plug in since the back end is
        # considered to be public.
        if not edge_host:
            if vpn_edge_host_header_required:
                # TODO: integrate glitchtip with turnpike and capture this so we get alert if it happens, see https://issues.redhat.com/browse/RHCLOUD-40788
                self.app.logger.info(
                    f'[backend: "{backend_name}"] Request denied. Missing mandatory "{HeaderValidator.EDGE_HOST_HEADER}" header for VPN restricted backend'
                )

                context.status_code = HTTPStatus.FORBIDDEN
                return context
            else:
                self.app.logger.debug(f'[backend: "{backend_name}"] VPN plugin skipped. Backend is not VPN restricted')
                return context

        # Make sure that the "edge host" header is valid.
        try:
            network: AllowedNetworks = self.header_validator.validate_edge_host_header(
                x_edge_host_header_value=edge_host
            )
        except InvalidHeader as ih:
            self.app.logger.error(
                f'[backend: "{backend_name}"][{HeaderValidator.EDGE_HOST_HEADER}: "{edge_host}"] Request denied. Invalid "edge host" header specified: {str(ih)}'
            )

            context.status_code = HTTPStatus.FORBIDDEN
            return context

        # When the "edge host" header indicates that the request comes from
        # the internal network, we need to check whether the back end is
        # VPN-restricted or not.
        #
        # When it is, we need to reject the request. Otherwise, the VPN plugin
        # needs to be skipped so that we don't set the Nginx header flag
        # indicating that the origin of the request is the private network.
        if network == AllowedNetworks.INTERNAL:
            if vpn_edge_host_header_required:
                self.app.logger.info(
                    f'[backend: "{backend_name}"][{HeaderValidator.EDGE_HOST_HEADER}: "{edge_host}"] Request denied. Backend requires the requests to come from the VPN'
                )

                context.status_code = HTTPStatus.FORBIDDEN
                return context
            else:
                self.app.logger.debug(
                    f'[backend: "{backend_name}"][{HeaderValidator.EDGE_HOST_HEADER}: "{edge_host}"] VPN plugin skipped. Backend is not VPN restricted'
                )
                return context

        self.app.logger.debug(
            f'[backend: "{backend_name}"][{HeaderValidator.EDGE_HOST_HEADER}: "{edge_host}"] Request successfully passed through the VPN plugin'
        )
        return context
