from app.models.models import Alert, SecurityLog, DetectionRule
from app.services.rule_loader import refresh_rules

def test_alerts_query_and_filtering(client, db_session):
    """
    Asserts GET /api/v1/alerts returns alerts and respects status/severity filters.
    """
    refresh_rules(db_session)
    
    # 1. Seed alert items
    rule = db_session.query(DetectionRule).first()
    log = SecurityLog(
        event_type="system",
        severity="INFO",
        message="System started",
        raw_payload="System startup payload"
    )
    db_session.add(log)
    db_session.commit()
    db_session.refresh(log)
    
    alert1 = Alert(
        rule_id=rule.id,
        trigger_log_id=log.id,
        title="SQL Injection attempt",
        description="Matched SELECT statement in query",
        severity="CRITICAL",
        status="NEW"
    )
    alert2 = Alert(
        rule_id=rule.id,
        trigger_log_id=log.id,
        title="Failed Login Attempts",
        description="SSH login attempt rate threshold crossed",
        severity="HIGH",
        status="ACKNOWLEDGED"
    )
    
    db_session.add(alert1)
    db_session.add(alert2)
    db_session.commit()
    
    # 2. Assert query list
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert len(response.json()) >= 2
    
    # 3. Assert severity filter
    response_critical = client.get("/api/v1/alerts?severity=CRITICAL")
    assert len(response_critical.json()) == 1
    assert response_critical.json()[0]["title"] == "SQL Injection attempt"
    
    # 4. Assert status filter
    response_ack = client.get("/api/v1/alerts?status=ACKNOWLEDGED")
    assert len(response_ack.json()) == 1
    assert response_ack.json()[0]["title"] == "Failed Login Attempts"

def test_update_alert_status_endpoint(client, db_session):
    """
    Asserts PUT /api/v1/alerts/{alert_id}/status updates the status field.
    """
    refresh_rules(db_session)
    rule = db_session.query(DetectionRule).first()
    log = SecurityLog(event_type="auth", severity="INFO", message="log", raw_payload="raw")
    db_session.add(log)
    db_session.commit()
    db_session.refresh(log)
    
    alert = Alert(
        rule_id=rule.id,
        trigger_log_id=log.id,
        title="Unusual traffic",
        description="Heavy egress bandwidth",
        severity="MEDIUM",
        status="NEW"
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    
    # Update status to ACKNOWLEDGED
    response = client.put(f"/api/v1/alerts/{alert.id}/status?alert_status=ACKNOWLEDGED")
    assert response.status_code == 200
    assert response.json()["status"] == "ACKNOWLEDGED"
    
    # Update status to an invalid state
    response_invalid = client.put(f"/api/v1/alerts/{alert.id}/status?alert_status=INVALID")
    assert response_invalid.status_code == 400

def test_analyze_alert_endpoint(client, db_session):
    """
    Asserts POST /api/v1/alerts/{alert_id}/analyze triggers AI playbook generation,
    caching the output in the DB, and returning it on subsequent requests.
    """
    refresh_rules(db_session)
    rule = db_session.query(DetectionRule).first()
    log = SecurityLog(
        event_type="auth", 
        severity="WARNING", 
        message="sshd[10101]: Failed password for admin", 
        raw_payload="sshd[10101]: Failed password for admin",
        source_ip="192.168.1.100"
    )
    db_session.add(log)
    db_session.commit()
    db_session.refresh(log)
    
    alert = Alert(
        rule_id=rule.id,
        trigger_log_id=log.id,
        title="Brute Force SSH Attack",
        description="SSH login attempt rate threshold crossed",
        severity="HIGH",
        status="NEW"
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    
    # 1. Trigger AI Analysis
    response = client.post(f"/api/v1/alerts/{alert.id}/analyze")
    assert response.status_code == 200
    
    data = response.json()
    assert data["ai_summary"] is not None
    assert "brute force" in data["ai_summary"].lower()
    assert data["ai_playbook"] is not None
    
    # Check that cache fields are populated in the database
    updated_alert = db_session.query(Alert).filter(Alert.id == alert.id).first()
    assert updated_alert.ai_summary == data["ai_summary"]
    
    # 2. Call again to verify it uses the cached response
    db_session.close() # Close connection to flush

