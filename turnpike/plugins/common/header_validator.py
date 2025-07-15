import re

from flask import Flask
from requests.exceptions import InvalidHeader

from turnpike.plugins.common.non_vpn_edge_host_header_error import NonVPNEdgeHostHeaderError


class HeaderValidator:
    EDGE_HOST_HEADER = "X-Rh-Edge-Host"

    def __init__(self, app: Flask):
        self.edge_host_regex = re.compile(
            r"(?:mtls\.)?(internal|private)\.(?:console|cloud)\.(?:(stage|dev)\.)?redhat\.com"
        )
        self.environment = app.config.get("WEB_ENV").casefold()

    def validate_edge_host_header_vpn(self, x_edge_host_header_value: str) -> None:
        """Validate that the value of the "edge host header" is a VPN host."""
        match = self.edge_host_regex.fullmatch(x_edge_host_header_value)

        if not match:
            raise InvalidHeader(
                f'[{HeaderValidator.EDGE_HOST_HEADER}: "{x_edge_host_header_value}"] Unrecognized edge host'
            )

        if match.groups()[0] != "private":
            raise NonVPNEdgeHostHeaderError(
                f'[{HeaderValidator.EDGE_HOST_HEADER}: "{x_edge_host_header_value}"] Request comes from a non-private network'
            )

        matched_environment: str = match.groups()[1]
        if self.is_env_production() and matched_environment:
            raise InvalidHeader(
                f'[{HeaderValidator.EDGE_HOST_HEADER}: "{x_edge_host_header_value}"] Request comes from a non-production environment'
            )
        elif not self.is_env_production() and not matched_environment:
            raise InvalidHeader(
                f'[{HeaderValidator.EDGE_HOST_HEADER}: "{x_edge_host_header_value}"] Request comes from a production environment'
            )

    def is_env_production(self):
        return self.environment == "prod" or self.environment == "production"
