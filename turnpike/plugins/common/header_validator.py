import re
from typing import Optional

from flask import Flask
from requests.exceptions import InvalidHeader

from turnpike.plugins.common.AllowedNetworks import AllowedNetworks


class HeaderValidator:
    EDGE_HOST_HEADER = "X-Rh-Edge-Host"

    def __init__(self, app: Flask):
        self.edge_host_regex = re.compile(
            r"(?:mtls\.)?(internal|private)\.(?:console|cloud)\.(?:(stage|dev)\.)?redhat\.com"
        )
        self.environment = app.config.get("WEB_ENV").casefold()

    def validate_edge_host_header(self, x_edge_host_header_value: str) -> AllowedNetworks:
        """Validate the "edge host" header's value.

        :param x_edge_host_header_value: The value of the "edge host" header to validate.
        :raises InvalidHeader: When the host is an unrecognized host.
        :raises InvalidHeader: When the host does not match the expected environment. For example, if the application is running in production the host has to match that environment.
        :returns: The network which was matched.
        """
        match: Optional[re.Match[str]] = self.edge_host_regex.fullmatch(x_edge_host_header_value)

        if not match:
            raise InvalidHeader("Unrecognized edge host")

        # Make sure that the "edge host" comes from an expected environment.
        matched_environment: Optional[str] = match.groups()[1]
        if self.is_env_production() and matched_environment:
            raise InvalidHeader("Request comes from a non-production environment")
        elif not self.is_env_production() and not matched_environment:
            raise InvalidHeader("Request comes from a production environment")

        # It is safe to assume that the matched group is one of the enum
        # values, since otherwise we would not have had a match in the first
        # place.
        if match.groups()[0] == AllowedNetworks.INTERNAL.value:
            return AllowedNetworks.INTERNAL
        else:
            return AllowedNetworks.PRIVATE

    def is_env_production(self) -> bool:
        """Verify if the application is running in the production environment.

        :returns: True if the application is running in the production environment.
        """
        return self.environment == "prod" or self.environment == "production"
