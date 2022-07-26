from prometheus_client import Counter, Histogram


class Metrics:
    request_count = Counter("requests", "Request Count", ["service", "policy_status_code"])


class AuthMetrics:
    auth_request_latency = Histogram(name="request_latency_ms", documentation="Response time for requests", labelnames=["auth_type"])
