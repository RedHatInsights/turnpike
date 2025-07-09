import ipaddress

from flask import current_app, request

from ..plugin import TurnpikePlugin, PolicyContext


class SourceIPPlugin(TurnpikePlugin):
    def process(self, context: PolicyContext) -> PolicyContext:
        if not context.backend.source_ip:
            return context

        # We count on the existence of an X-Forwarded-For header, given the policy service is proxied to at least by
        # the nginx server and possibly by more. If there were more proxies, we need to have been configured with the
        # number of forwards to the edge proxy so we can establish the true client IP.
        try:
            hops = request.headers["X-Forwarded-For"].split(", ")
            hops_to_edge = current_app.config.get("HOPS_TO_EDGE", 0)
            client_ip = ipaddress.ip_address(hops[-1 * (hops_to_edge + 1)])
        except ValueError:
            # Edge wasn't in the hop list or hop list is malformed
            current_app.logger.exception(f"Invalid X-Forwarded-For hop list found: {hops}")
            context.status_code = 403
            return context
        allowed_ip_networks = [ipaddress.ip_network(cidr) for cidr in context.backend.source_ip]
        current_app.logger.debug(
            f"hops {hops}, hops_to_edge {hops_to_edge}, allowed_ip_networks {allowed_ip_networks}"
        )
        if not any(
            [client_ip in net for net in filter(lambda net: net.version == client_ip.version, allowed_ip_networks)]
        ):
            current_app.logger.debug(f"Client IP {client_ip} not in allowed networks for this route.")
            context.status_code = 403
        return context
