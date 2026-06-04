import logging
import json
import sys
from datetime import datetime, timezone

class GoogleJsonFormatter(logging.Formatter):
    """
    Formatter that outputs structured logs in Google Cloud Logging compatible JSON format.
    """
    def format(self, record):
        log_entry = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "logging.googleapis.com/sourceLocation": {
                "file": record.pathname,
                "line": record.lineno,
                "function": record.funcName
            }
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_entry)

# Set up the logger
logger = logging.getLogger("siem_backend")
logger.setLevel(logging.INFO)

# Add stdout handler with Google JSON Formatter
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(GoogleJsonFormatter())
    logger.addHandler(handler)
