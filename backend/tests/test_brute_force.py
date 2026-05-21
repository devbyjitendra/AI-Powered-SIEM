from app.models.models import SecurityLog, Alert
from app.services.rule_loader import refresh_rules
from app.services.correlation_engine import correlate_log

def test_credential_stuffing_detection(db_session):
    """
    Tests that a single source IP hitting 3+ different user accounts
    triggers a Credential Stuffing Alert.
    """
    refresh_rules(db_session)
    
    ip_source = "192.168.1.55"
    users_list = ["admin", "root", "guest"]
    
    for user in users_list:
        log = SecurityLog(
            event_type="auth",
            severity="WARNING",
            message=f"Failed login attempt for user {user}",
            raw_payload=f"Failed login attempt for user {user}",
            source_ip=ip_source,
            user_id=user
        )
        db_session.add(log)
        db_session.commit()
        db_session.refresh(log)
        correlate_log(log, db_session)
        
    alerts = db_session.query(Alert).filter(Alert.title == "Credential Stuffing Detected").all()
    assert len(alerts) == 1
    assert ip_source in alerts[0].description
    assert "3 unique usernames" in alerts[0].description

def test_distributed_brute_force_detection(db_session):
    """
    Tests that multiple unique source IPs hitting the SAME target user
    triggers a Distributed Brute Force Alert.
    """
    refresh_rules(db_session)
    
    target_user = "supervisor_admin"
    ips_list = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    
    for ip in ips_list:
        log = SecurityLog(
            event_type="auth",
            severity="WARNING",
            message=f"Failed login attempt for user {target_user}",
            raw_payload=f"Failed login attempt for user {target_user}",
            source_ip=ip,
            user_id=target_user
        )
        db_session.add(log)
        db_session.commit()
        db_session.refresh(log)
        correlate_log(log, db_session)
        
    alerts = db_session.query(Alert).filter(Alert.title == "Distributed Brute Force Alert").all()
    assert len(alerts) == 1
    assert target_user in alerts[0].description
    assert "3 unique IP sources" in alerts[0].description
