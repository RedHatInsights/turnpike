import ipaddress

from flask import current_app, request

from ..plugin import TurnpikePlugin


class SourceIPPlugin(TurnpikePlugin):
    def process(self, context):
        if "source_ip" not in context.backend:
            return context

        # We count on the existence of an X-Forwarded-For header, given the policy service is proxied to at least by
        # the nginx server and possibly by more. If there were more proxies, we need to have been configured with the
        # IP address of the edge proxy so we can establish the edge's client IP.
        try:
            hops = request.headers["X-Forwarded-For"].split(", ")
            if current_app.config.get("EDGE_PROXY_IP"):
                edge_hop_idx = hops.index(current_app.config["EDGE_PROXY_IP"])
                if edge_hop_idx == 0:
                    raise ValueError("Edge was first hop in X-Forwarded-For")
                client_ip = ipaddress.ip_address(hops[edge_hop_idx - 1])
            else:
                client_ip = ipaddress.ip_address(hops[0])
        except ValueError:
            # Edge wasn't in the hop list or hop list is malformed
            current_app.logger.exception(f"Invalid X-Forwarded-For hop list found: {hops}")
            context.status_code = 403
            return context
        allowed_ip_networks = [ipaddress.ip_network(cidr) for cidr in context.backend["source_ip"]]
        if not any(
            [client_ip in net for net in filter(lambda net: net.version == client_ip.version, allowed_ip_networks)]
        ):
            current_app.logger.debug(f"Client IP {client_ip} not in allowed networks for this route.")
            context.status_code = 403
        return context
