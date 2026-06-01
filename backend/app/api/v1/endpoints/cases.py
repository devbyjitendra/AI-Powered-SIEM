from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.core.database import get_db
from app.core.logging import logger
from app.models.models import IncidentCase, Alert
from app.models.schemas import IncidentCaseCreate, IncidentCaseUpdate, IncidentCaseResponse

router = APIRouter()

@router.get("", response_model=List[IncidentCaseResponse])
def get_cases(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Retrieve all security incident cases, with optional filtering by status (OPEN, IN_PROGRESS, CLOSED)
    or severity (LOW, MEDIUM, HIGH, CRITICAL).
    """
    query = db.query(IncidentCase)
    if status:
        query = query.filter(IncidentCase.status == status.upper())
    if severity:
        query = query.filter(IncidentCase.severity == severity.upper())
    return query.order_by(IncidentCase.created_at.desc()).all()

@router.post("", response_model=IncidentCaseResponse, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: IncidentCaseCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new security incident investigation ticket.
    """
    try:
        db_case = IncidentCase(
            title=payload.title,
            severity=payload.severity.upper(),
            assigned_to=payload.assigned_to,
            status="OPEN"
        )
        db.add(db_case)
        db.commit()
        db.refresh(db_case)
        logger.info(f"Incident Case '{db_case.title}' created with ID {db_case.id}.")
        return db_case
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to create case: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create security incident case."
        )

@router.get("/{case_id}", response_model=IncidentCaseResponse)
def get_case_details(
    case_id: int,
    db: Session = Depends(get_db)
):
    """
    Fetch details and associated alerts for a specific incident case.
    """
    db_case = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()
    if not db_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident case with ID {case_id} not found."
        )
    return db_case

@router.put("/{case_id}", response_model=IncidentCaseResponse)
def update_case_details(
    case_id: int,
    payload: IncidentCaseUpdate,
    db: Session = Depends(get_db)
):
    """
    Modify an ongoing security case, updating its status, severity, title, or assignee.
    """
    db_case = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()
    if not db_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident case with ID {case_id} not found."
        )
        
    try:
        if payload.title is not None:
            db_case.title = payload.title
        if payload.status is not None:
            db_case.status = payload.status.upper()
        if payload.severity is not None:
            db_case.severity = payload.severity.upper()
        if payload.assigned_to is not None:
            db_case.assigned_to = payload.assigned_to
            
        db.commit()
        db.refresh(db_case)
        logger.info(f"Incident Case ID {case_id} successfully updated.")
        return db_case
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update case details: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not update incident case details."
        )

@router.post("/{case_id}/alerts", response_model=IncidentCaseResponse)
def link_alert_to_case(
    case_id: int,
    alert_id: int,
    db: Session = Depends(get_db)
):
    """
    Links a specific security alert to an incident case investigation.
    """
    db_case = db.query(IncidentCase).filter(IncidentCase.id == case_id).first()
    if not db_case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident case with ID {case_id} not found."
        )
        
    db_alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not db_alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found."
        )
        
    try:
        db_alert.case_id = case_id
        db.commit()
        db.refresh(db_case)
        logger.info(f"Linked Alert ID {alert_id} to Incident Case ID {case_id}.")
        return db_case
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to link alert to case: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while linking alert to case."
        )
