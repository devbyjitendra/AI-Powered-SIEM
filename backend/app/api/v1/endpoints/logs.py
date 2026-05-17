from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.core.database import get_db
from app.core.logging import logger
from app.models.models import SecurityLog
from app.models.schemas import BulkLogIngestionRequest, SecurityLogResponse, SecurityLogCreate, LogIngestionResponse
from app.services.parser_service import resolve_geoip, parse_user_agent
from app.services.queue_service import enqueue_logs

router = APIRouter()

@router.post("/ingest", response_model=LogIngestionResponse, status_code=status.HTTP_201_CREATED)
async def ingest_logs(payload: BulkLogIngestionRequest, async_mode: bool = False, db: Session = Depends(get_db)):
    """
    Ingest a batch of structured security logs.
    Supports synchronous DB writes (default) or high-throughput async processing via background queues.
    """
    if async_mode:
        await enqueue_logs(payload.logs)
        return LogIngestionResponse(
            status="queued",
            message="Logs successfully added to processing queue.",
            count=len(payload.logs)
        )

    logger.info(f"Ingesting a batch of {len(payload.logs)} logs (sync)...")
    
    db_logs = []
    try:
        for log_data in payload.logs:
            # Auto-enrich geo location and user agent information
            geo = log_data.geo_country or resolve_geoip(log_data.source_ip)
            ua = parse_user_agent(log_data.user_agent) if log_data.user_agent else "System Agent"
            
            db_log = SecurityLog(
                event_type=log_data.event_type,
                severity=log_data.severity,
                message=log_data.message,
                raw_payload=log_data.raw_payload,
                source_ip=log_data.source_ip,
                destination_ip=log_data.destination_ip,
                source_port=log_data.source_port,
                destination_port=log_data.destination_port,
                geo_country=geo,
                user_agent=ua,
                user_id=log_data.user_id,
                timestamp=log_data.timestamp
            )
            db.add(db_log)
            db_logs.append(db_log)
        
        db.commit()
        
        # Refresh the database records to populate the generated IDs and default values
        for db_log in db_logs:
            db.refresh(db_log)
            
        logger.info(f"Successfully ingested {len(db_logs)} logs.")
        return LogIngestionResponse(
            status="success",
            message="Logs processed synchronously and persisted to database.",
            count=len(db_logs),
            logs=db_logs
        )
        
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to ingest logs: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while saving the logs to the database."
        )
