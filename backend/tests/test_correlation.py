from app.models.models import SecurityLog, Alert, DetectionRule
from app.services.rule_loader import refresh_rules
from app.services.correlation_engine import correlate_log

def test_signature_alert_generation(db_session):
    """
    Tests that a log containing a SQL Injection pattern triggers
    a database Alert immediately through signature matching.
    """
    # Initialize the rules cache registry
    refresh_rules(db_session)
    
    # Create the malicious log entry
    malicious_log = SecurityLog(
        event_type="web",
        severity="INFO",
        message="GET /index.php?id=1 UNION SELECT username, password FROM users--",
        raw_payload="GET /index.php?id=1 UNION SELECT username, password FROM users--",
        source_ip="203.0.113.45"
    )
    db_session.add(malicious_log)
    db_session.commit()
    db_session.refresh(malicious_log)
    
    # Run correlation engine
    correlate_log(malicious_log, db_session)
    
    # Check if Alert was generated
    alert = db_session.query(Alert).filter(Alert.trigger_log_id == malicious_log.id).first()
    assert alert is not None
    assert alert.rule_id == "RULE-WEB-SQLI"
    assert alert.severity == "CRITICAL"
    assert "SQL Injection" in alert.title

def test_brute_force_rate_alert(db_session):
    """
    Tests that 5 failed login attempts from the same IP trigger
    a Brute Force Alert.
    """
    refresh_rules(db_session)
    
    ip_address = "185.199.108.153"
    
    # Generate 5 failed login logs
    for i in range(5):
        log = SecurityLog(
            event_type="auth",
            severity="WARNING",
            message="Failed password for invalid user admin",
            raw_payload="sshd: Failed password for admin",
            source_ip=ip_address
        )
        db_session.add(log)
        db_session.commit()
        db_session.refresh(log)
        
        # Correlate this log
        correlate_log(log, db_session)
        
    # Check if a brute-force alert was generated
    alerts = db_session.query(Alert).filter(Alert.rule_id == "RULE-AUTH-BRUTEFORCE").all()
    assert len(alerts) == 1
    
    alert = alerts[0]
    assert alert.severity == "HIGH"
    assert ip_address in alert.description
