import pytest
from pydantic import ValidationError
from app.models.schemas import SecurityLogCreate, BulkLogIngestionRequest

def test_log_sanitization():
    """
    Verifies that potentially malicious script and HTML tags are sanitized
    from log messages and raw payloads.
    """
    xss_message = "<script>alert('XSS')</script>Failed SSH attempt"
    clean_message = "alert('XSS')Failed SSH attempt"

    log = SecurityLogCreate(
        event_type="auth",
        severity="WARNING",
        message=xss_message,
        raw_payload="<svg onload=alert(1)> raw payload"
    )

    assert log.message == clean_message
    assert log.raw_payload == " raw payload"

def test_bulk_log_ingestion_validation():
    """
    Verifies that BulkLogIngestionRequest correctly validates a list of logs.
    """
    payload = {
        "logs": [
            {
                "event_type": "web",
                "severity": "INFO",
                "message": "GET /index.html",
                "raw_payload": "HTTP GET /index.html from 1.1.1.1",
                "source_ip": "1.1.1.1"
            },
            {
                "event_type": "auth",
                "severity": "ERROR",
                "message": "Failed login",
                "raw_payload": "Failed login for admin",
                "source_ip": "1.1.1.2"
            }
        ]
    }

    bulk_req = BulkLogIngestionRequest(**payload)
    assert len(bulk_req.logs) == 2
    assert bulk_req.logs[0].event_type == "web"
    assert bulk_req.logs[1].source_ip == "1.1.1.2"

def test_invalid_log_missing_fields():
    """
    Ensures that missing mandatory fields (like event_type or severity) raise a validation error.
    """
    with pytest.raises(ValidationError):
        SecurityLogCreate(
            message="Missing fields log",
            raw_payload="No event type"
        )
