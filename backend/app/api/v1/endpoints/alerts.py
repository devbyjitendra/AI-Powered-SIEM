import json
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.core.logging import logger
from app.models.models import Alert
from app.models.schemas import AlertResponse
from app.services.gemini_service import generate_security_playbook, ask_gemini_assistant, stream_gemini_assistant
from fastapi.responses import StreamingResponse

router = APIRouter()

@router.get("", response_model=List[AlertResponse])
def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """
    Retrieve all security alerts, with optional filtering by status (NEW, ACKNOWLEDGED, RESOLVED),
    severity (LOW, MEDIUM, HIGH, CRITICAL), or time range.
    """
    query = db.query(Alert)
    
    if status:
        query = query.filter(Alert.status == status.upper())
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if start_time:
        query = query.filter(Alert.timestamp >= start_time.replace(tzinfo=None))
    if end_time:
        query = query.filter(Alert.timestamp <= end_time.replace(tzinfo=None))
        
    # Order by newest alerts first, limit to 250 to avoid relationship stitching bottlenecks
    return query.order_by(Alert.timestamp.desc()).limit(250).all()

@router.put("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    alert_status: str,
    db: Session = Depends(get_db)
):
    """
    Updates the operational investigation status of a security alert.
    """
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found."
        )
        
    status_upper = alert_status.upper()
    if status_upper not in ["NEW", "ACKNOWLEDGED", "RESOLVED"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid status. Must be one of: NEW, ACKNOWLEDGED, RESOLVED"
        )
        
    try:
        db_alert.status = status_upper
        db.commit()
        db.refresh(db_alert)
        logger.info(f"Alert ID {alert_id} status updated to {status_upper}.")
        return db_alert
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update alert status: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the alert status."
        )

@router.post("/{alert_id}/analyze", response_model=AlertResponse)
async def analyze_alert_endpoint(
    alert_id: int,
    db: Session = Depends(get_db)
):
    """
    Triggers Google Gemini AI security analysis on a specific alert,
    caching the resulting playbook and summary into the database.
    If already analyzed, returns cached playbook directly.
    """
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found."
        )
        
    # Check cache first
    if db_alert.ai_summary and db_alert.ai_playbook:
        logger.info(f"Returning cached AI playbook for Alert ID {alert_id}")
        return db_alert
        
    # Load associated rule and triggering log context
    rule_pattern = db_alert.rule.pattern if db_alert.rule else "Unknown Rule Pattern"
    log_message = db_alert.trigger_log.message if db_alert.trigger_log else "No triggering log message"
    source_ip = db_alert.trigger_log.source_ip if (db_alert.trigger_log and db_alert.trigger_log.source_ip) else "Unknown"
    
    # Generate the playbook
    playbook_data = await generate_security_playbook(
        title=db_alert.title,
        description=db_alert.description,
        severity=db_alert.severity,
        log_message=log_message,
        rule_pattern=rule_pattern,
        source_ip=source_ip
    )
    
    summary = playbook_data.get("analysis_summary", "No summary generated.")
    playbook_json_str = json.dumps(playbook_data)
    
    try:
        db_alert.ai_summary = summary
        db_alert.ai_playbook = playbook_json_str
        db.commit()
        db.refresh(db_alert)
        logger.info(f"AI analysis successfully cached for Alert ID {alert_id}.")
        return db_alert
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to save AI playbook cache: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not persist AI analysis to the database."
        )

@router.post("/chat")
async def ask_ai_chat_endpoint(
    payload: dict
):
    """
    Accepts a user chat prompt and streams the AI Security Assistant response.
    """
    prompt = payload.get("prompt", "")
    if not prompt:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Prompt cannot be empty."
        )
    
    return StreamingResponse(
        stream_gemini_assistant(prompt),
        media_type="text/plain"
    )

