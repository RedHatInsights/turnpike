import ipaddress

from flask import current_app, request

from ..plugin import TurnpikePlugin


class SourceIPPlugin(TurnpikePlugin):
    def process(self, context):
        if "source_ip" not in context.backend:
            return context
        client_ip = context.client_ip
        allowed_ip_networks = [ipaddress.ip_network(cidr) for cidr in context.backend["source_ip"]]
        if not client_ip or not any(
            [client_ip in net for net in filter(lambda net: net.version == client_ip.version, allowed_ip_networks)]
        ):
            context.result += "Client IP not in allowed networks for this route. "
            context.status_code = 403
        return context
