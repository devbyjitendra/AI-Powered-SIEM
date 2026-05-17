import asyncio
import pytest
from app.models.models import SecurityLog
from app.services.queue_service import log_queue

def test_async_log_ingestion_api(client):
    """
    Asserts that passing async_mode=true returns a 'queued' status payload
    and does not write directly to DB synchronously.
    """
    payload = {
        "logs": [
            {
                "event_type": "firewall",
                "severity": "INFO",
                "message": "Connection allowed",
                "raw_payload": "kernel: ALLOWET outbound connection",
                "source_ip": "10.0.0.1"
            }
        ]
    }
    
    # Verify starting state: queue is empty
    assert log_queue.empty()
    
    response = client.post("/api/v1/logs/ingest?async_mode=true", json=payload)
    assert response.status_code == 201
    
    data = response.json()
    assert data["status"] == "queued"
    assert data["count"] == 1
    assert data["logs"] is None
    
    # Verify item was added to the in-memory queue
    assert not log_queue.empty()
    
    # Clean up the queue item to prevent bleeding into other tests
    log_queue.get_nowait()
    log_queue.task_done()

@pytest.mark.asyncio
async def test_queue_worker_execution(db_session):
    """
    Directly tests that running the background worker processes items in the queue
    and saves them to the provided DB session.
    """
    from app.services.queue_service import log_worker
    from app.models.schemas import SecurityLogCreate
    
    log_item = SecurityLogCreate(
        event_type="system",
        severity="INFO",
        message="Service started",
        raw_payload="systemd: Started audit log daemon"
    )
    
    await log_queue.put(log_item)
    
    # Run the worker task in the background
    worker = asyncio.create_task(log_worker())
    
    # Wait for the queue to be fully processed
    await log_queue.join()
    
    # Cancel worker loop
    worker.cancel()
    try:
        await worker
    except asyncio.CancelledError:
        pass
        
    # Assert item was written to database
    db_log = db_session.query(SecurityLog).filter(SecurityLog.event_type == "system").first()
    assert db_log is not None
    assert db_log.message == "Service started"
    assert db_log.geo_country == "Unknown"
