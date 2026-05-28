import re
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List
from sqlalchemy.orm import Session
from fastapi.encoders import jsonable_encoder

from app.models.models import SecurityLog, Alert, DetectionRule
from app.services.rule_loader import get_active_rules
from app.core.logging import logger
from app.services.websocket_manager import manager
from app.models.schemas import AlertResponse

# In-memory databases to track sliding-window failed logins
_brute_force_tracker: Dict[str, List[datetime]] = {}
# Tracks (timestamp, user_id) targeted by a single source IP
_cred_stuffing_tracker: Dict[str, List[tuple]] = {}
# Tracks (timestamp, source_ip) targeting a single username
_dist_brute_force_tracker: Dict[str, List[tuple]] = {}

WINDOW_SECONDS = 60
THRESHOLD_FAILED_ATTEMPTS = 5
THRESHOLD_CRED_STUFFING_USERS = 3
THRESHOLD_DIST_IP_SOURCES = 3

def correlate_log(log: SecurityLog, db: Session) -> None:
    """
    Evaluates a single security log against active rules.
    Triggers database Alerts when rules are matched or thresholds are breached.
    """
    active_rules = get_active_rules()
    
    for rule in active_rules:
        # 1. Regex Pattern Matching
        if re.search(rule.pattern, log.message):
            
            # Special correlation logic for Brute Force (rate-based threshold checks)
            if rule.id == "RULE-AUTH-BRUTEFORCE":
                if not log.source_ip:
                    continue
                _process_brute_force(log, rule, db)
                _process_credential_stuffing(log, rule, db)
                _process_distributed_brute_force(log, rule, db)
            
            # Simple signature rules trigger alerts immediately
            else:
                _trigger_alert(
                    db=db,
                    rule=rule,
                    log=log,
                    title=f"Signature Match: {rule.name}",
                    description=f"Log matched signature rule '{rule.name}'. Pattern found: '{rule.pattern}'"
                )

def _process_brute_force(log: SecurityLog, rule: DetectionRule, db: Session) -> None:
    """
    Tracks failed login attempts by IP in memory and triggers alert if rate threshold is crossed.
    """
    global _brute_force_tracker
    ip = log.source_ip
    now = datetime.utcnow()
    
    # Initialize list if first time
    if ip not in _brute_force_tracker:
        _brute_force_tracker[ip] = []
        
    # Append current failure
    _brute_force_tracker[ip].append(now)
    
    # Prune old timestamps outside the sliding window
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    _brute_force_tracker[ip] = [ts for ts in _brute_force_tracker[ip] if ts > cutoff]
    
    failed_count = len(_brute_force_tracker[ip])
    logger.debug(f"Failed logins from {ip} in last {WINDOW_SECONDS}s: {failed_count}/{THRESHOLD_FAILED_ATTEMPTS}")
    
    # Check threshold breach
    if failed_count >= THRESHOLD_FAILED_ATTEMPTS:
        _brute_force_tracker[ip] = []
        _trigger_alert(
            db=db,
            rule=rule,
            log=log,
            title=f"Brute Force Alert: {rule.name}",
            description=f"Multiple failed login attempts ({failed_count} failures) detected from IP {ip} within {WINDOW_SECONDS} seconds."
        )

def _process_credential_stuffing(log: SecurityLog, rule: DetectionRule, db: Session) -> None:
    """
    Tracks failed login attempts by source IP targeting different users.
    Triggers alert if multiple unique users are targeted from the same IP.
    """
    global _cred_stuffing_tracker
    ip = log.source_ip
    user = log.user_id or "unknown_user"
    now = datetime.utcnow()
    
    if ip not in _cred_stuffing_tracker:
        _cred_stuffing_tracker[ip] = []
        
    _cred_stuffing_tracker[ip].append((now, user))
    
    # Prune old entries
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    _cred_stuffing_tracker[ip] = [item for item in _cred_stuffing_tracker[ip] if item[0] > cutoff]
    
    # Count unique users targeted
    unique_users = {item[1] for item in _cred_stuffing_tracker[ip]}
    
    if len(unique_users) >= THRESHOLD_CRED_STUFFING_USERS:
        _cred_stuffing_tracker[ip] = [] # Reset
        _trigger_alert(
            db=db,
            rule=rule,
            log=log,
            title="Credential Stuffing Detected",
            description=f"Source IP {ip} targeted {len(unique_users)} unique usernames in a brute-force pattern within {WINDOW_SECONDS} seconds."
        )

def _process_distributed_brute_force(log: SecurityLog, rule: DetectionRule, db: Session) -> None:
    """
    Tracks failed login attempts targeting a single user from different IPs.
    """
    global _dist_brute_force_tracker
    user = log.user_id
    ip = log.source_ip
    now = datetime.utcnow()
    
    if not user:
        return
        
    if user not in _dist_brute_force_tracker:
        _dist_brute_force_tracker[user] = []
        
    _dist_brute_force_tracker[user].append((now, ip))
    
    cutoff = now - timedelta(seconds=WINDOW_SECONDS)
    _dist_brute_force_tracker[user] = [item for item in _dist_brute_force_tracker[user] if item[0] > cutoff]
    
    # Count unique IPs targeting this user
    unique_ips = {item[1] for item in _dist_brute_force_tracker[user]}
    
    if len(unique_ips) >= THRESHOLD_DIST_IP_SOURCES:
        _dist_brute_force_tracker[user] = []
        _trigger_alert(
            db=db,
            rule=rule,
            log=log,
            title="Distributed Brute Force Alert",
            description=f"Target account '{user}' targeted by {len(unique_ips)} unique IP sources within {WINDOW_SECONDS} seconds."
        )


def _trigger_alert(db: Session, rule: DetectionRule, log: SecurityLog, title: str, description: str) -> None:
    """
    Creates and commits a new alert record to the database, and broadcasts it to connected WebSocket clients.
    """
    logger.warning(f"🚨 ALERT TRIGGERED: {title} - {description}")
    try:
        alert = Alert(
            rule_id=rule.id,
            trigger_log_id=log.id,
            title=title,
            description=description,
            severity=rule.severity,
            status="NEW"
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        
        # Broadcast the alert via WebSocket
        alert_data = jsonable_encoder(AlertResponse.from_orm(alert))
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(manager.broadcast(alert_data))
        except RuntimeError:
            # Fallback if there is no running loop in the current thread
            asyncio.run(manager.broadcast(alert_data))
            
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to save and broadcast alert: {e}", exc_info=True)

