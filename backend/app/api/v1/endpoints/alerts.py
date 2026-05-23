from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.core.logging import logger
from app.models.models import Alert
from app.models.schemas import AlertResponse

router = APIRouter()

@router.get("", response_model=List[AlertResponse])
def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Retrieve all security alerts, with optional filtering by status (NEW, ACKNOWLEDGED, RESOLVED)
    or severity (LOW, MEDIUM, HIGH, CRITICAL).
    """
    query = db.query(Alert)
    
    if status:
        query = query.filter(Alert.status == status.upper())
    if severity:
        query = query.filter(Alert.severity == severity.upper())
        
    # Order by newest alerts first
    return query.order_by(Alert.timestamp.desc()).all()

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
