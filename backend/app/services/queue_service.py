import asyncio
from typing import List
from app.core.database import SessionLocal
from app.core.logging import logger
from app.models.models import SecurityLog
from app.models.schemas import SecurityLogCreate
from app.services.parser_service import resolve_geoip, parse_user_agent

# Thread-safe asyncio Queue
log_queue = asyncio.Queue()
_worker_task = None

async def enqueue_logs(logs: List[SecurityLogCreate]) -> None:
    """
    Enqueues a list of raw/validated logs for asynchronous database insertion.
    """
    for log_data in logs:
        await log_queue.put(log_data)
    logger.debug(f"Queued {len(logs)} logs for background processing. Current queue size: {log_queue.qsize()}")


async def log_worker() -> None:
    """
    Background worker loop that continuously fetches logs from the queue
    and persists them to the database in micro-batches.
    """
    logger.info("Starting background log processing worker...")
    while True:
        try:
            # Wait for a log to become available
            log_data = await log_queue.get()
            
            # Fetch additional queued logs to process as a batch
            batch = [log_data]
            while not log_queue.empty() and len(batch) < 100:
                batch.append(log_queue.get_nowait())
                
            logger.debug(f"Processing batch of {len(batch)} logs from queue...")
            
            db = SessionLocal()
            try:
                for item in batch:
                    # Enrich Geo-IP and User-Agent
                    geo = item.geo_country or resolve_geoip(item.source_ip)
                    ua = parse_user_agent(item.user_agent) if item.user_agent else "System Agent"
                    
                    db_log = SecurityLog(
                        event_type=item.event_type,
                        severity=item.severity,
                        message=item.message,
                        raw_payload=item.raw_payload,
                        source_ip=item.source_ip,
                        destination_ip=item.destination_ip,
                        source_port=item.source_port,
                        destination_port=item.destination_port,
                        geo_country=geo,
                        user_agent=ua,
                        user_id=item.user_id,
                        timestamp=item.timestamp
                    )
                    db.add(db_log)
                db.commit()
            except Exception as e:
                db.rollback()
                logger.error(f"Error persisting async batch to database: {e}", exc_info=True)
            finally:
                db.close()
                
            # Signal task completion for each item in the batch
            for _ in range(len(batch)):
                log_queue.task_done()
                
        except asyncio.CancelledError:
            logger.info("Background log worker task cancelled.")
            break
        except Exception as e:
            logger.error(f"Unexpected error in background log worker: {e}", exc_info=True)
            await asyncio.sleep(1) # Simple backoff before retrying loop


def start_worker() -> None:
    """
    Initializes and starts the background worker task.
    """
    global _worker_task
    if _worker_task is None:
        _worker_task = asyncio.create_task(log_worker())
        logger.info("Background log worker task launched.")


async def stop_worker() -> None:
    """
    Gracefully stops the background worker task.
    """
    global _worker_task
    if _worker_task is not None:
        # Process remaining items before shutting down
        logger.info("Stopping background log worker task, waiting for queue to drain...")
        # Cancel the task
        _worker_task.cancel()
        try:
            await _worker_task
        except asyncio.CancelledError:
            pass
        _worker_task = None
        logger.info("Background log worker task shut down.")
