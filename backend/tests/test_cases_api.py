from app.models.models import IncidentCase, Alert, SecurityLog, DetectionRule
from app.services.rule_loader import refresh_rules

def test_create_and_query_cases(client, db_session):
    """
    Asserts case creation and listing works.
    """
    # 1. Create a case
    payload = {
        "title": "Brute Force SSH investigation",
        "severity": "HIGH",
        "assigned_to": "SOC Analyst 1"
    }
    response = client.post("/api/v1/cases", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Brute Force SSH investigation"
    assert data["status"] == "OPEN"
    assert data["severity"] == "HIGH"
    
    # 2. Get cases list
    response_list = client.get("/api/v1/cases")
    assert response_list.status_code == 200
    assert len(response_list.json()) >= 1
    
    # 3. Filter list
    response_filt = client.get("/api/v1/cases?severity=HIGH")
    assert len(response_filt.json()) >= 1

def test_update_case_status_endpoint(client, db_session):
    """
    Asserts updating case fields like status and assignee.
    """
    case = IncidentCase(
        title="SQLi Injection Threat",
        severity="CRITICAL",
        status="OPEN",
        assigned_to="Unassigned"
    )
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    
    update_payload = {
        "status": "IN_PROGRESS",
        "assigned_to": "Security Admin"
    }
    response = client.put(f"/api/v1/cases/{case.id}", json=update_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "IN_PROGRESS"
    assert data["assigned_to"] == "Security Admin"

def test_link_alert_to_case_endpoint(client, db_session):
    """
    Asserts security alerts can be dynamically linked to incident cases.
    """
    refresh_rules(db_session)
    rule = db_session.query(DetectionRule).first()
    log = SecurityLog(event_type="web", severity="ERROR", message="log", raw_payload="raw")
    db_session.add(log)
    db_session.commit()
    db_session.refresh(log)
    
    alert = Alert(
        rule_id=rule.id,
        trigger_log_id=log.id,
        title="Malicious injection",
        description="SQL injection",
        severity="CRITICAL",
        status="NEW"
    )
    case = IncidentCase(
        title="Web Exploit Investigation",
        severity="CRITICAL",
        status="OPEN"
    )
    db_session.add(alert)
    db_session.add(case)
    db_session.commit()
    db_session.refresh(alert)
    db_session.refresh(case)
    
    # Link alert to case
    response = client.post(f"/api/v1/cases/{case.id}/alerts?alert_id={alert.id}")
    assert response.status_code == 200
    
    # Verify alert is linked
    linked_alert = db_session.query(Alert).filter(Alert.id == alert.id).first()
    assert linked_alert.case_id == case.id
