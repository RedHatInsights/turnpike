from prometheus_client import Counter, Histogram


class Metrics:
    request_count = Counter("requests", "Request Count", ["service", "policy_status_code"])
    request_latency = Histogram("request_latency", "Latency of Requests", ["service"])


class AuthMetrics:
    auth_request_latency = Histogram("auth_request_latency", "Response time for requests", ["auth_type"])
    auth_request_status = Counter("auth_request_status", "Response status code for auth plugins", ["auth_type", "status_code"])
