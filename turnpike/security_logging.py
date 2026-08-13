import json
import logging
from datetime import datetime, timezone

from flask import request

logger = logging.getLogger("turnpike.security")
logger.setLevel(logging.INFO)


def log_security_event(event_type, principal="unknown", status_code=None, backend=None, **extra):
    source_ip = _get_source_ip()
    record = {
        "event": event_type,
        "principal": principal,
        "source_ip": source_ip,
        "status_code": status_code,
        "backend": backend,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    record.update(extra)
    logger.info(json.dumps(record, sort_keys=True))


def _get_source_ip():
    try:
        return request.remote_addr or "unknown"
    except RuntimeError:
        return "unknown"
