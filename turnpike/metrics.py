from prometheus_client import Counter


class Metrics:
    request_count = Counter("requests", "Request Count", ["service", "policy_status_code"])
