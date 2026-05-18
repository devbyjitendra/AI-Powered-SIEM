import asyncio
import pytest
from app.models.models import SecurityLog
from app.services.queue_service import log_queue, log_worker

@pytest.mark.asyncio
async def test_high_concurrency_queue_ingestion(db_session, client):
    """
    Simulates high concurrent log uploads. Enqueues 100 logs concurrently 
    using asyncio, then executes the worker to verify database stability.
    """
    total_logs = 100
    
    # 1. Fire concurrent requests simulating multiple clients submitting logs at once
    async def post_log(index: int):
        payload = {
            "logs": [
                {
                    "event_type": "auth" if index % 2 == 0 else "firewall",
                    "severity": "WARNING" if index % 10 == 0 else "INFO",
                    "message": f"Concurrent log message #{index}",
                    "raw_payload": f"Raw log payload details for message #{index}",
                    "source_ip": f"192.168.1.{index}"
                }
            ]
        }
        # Client handles requests synchronously, but we can simulate concurrency using asyncio.gather
        # calling client.post directly (which runs blocking, but we wrap in run_in_executor or call in loops)
        # For tests, we can directly enqueue to log_queue or run client POST requests.
        # Since TestClient is synchronous, we run it in threadpools or call bulk directly.
        # Let's perform a bulk concurrent enqueue:
        response = client.post("/api/v1/logs/ingest?async_mode=true", json=payload)
        assert response.status_code == 201
        assert response.json()["status"] == "queued"

    # Execute 100 uploads concurrently
    await asyncio.gather(*(post_log(i) for i in range(total_logs)))
    
    # Assert queue size matches the total logs ingested
    assert log_queue.qsize() == total_logs
    
    # 2. Run background log worker task to drain the queue and persist items to DB
    worker = asyncio.create_task(log_worker())
    
    # Wait for all tasks to be marked complete
    await log_queue.join()
    
    # Clean up background worker
    worker.cancel()
    try:
        await worker
    except asyncio.CancelledError:
        pass
        
    # 3. Assert database contains all 100 records
    record_count = db_session.query(SecurityLog).count()
    assert record_count == total_logs
    
    # Check that data is properly normalized
    sample_log = db_session.query(SecurityLog).filter(SecurityLog.source_ip == "192.168.1.10").first()
    assert sample_log is not None
    assert sample_log.message == "Concurrent log message #10"
    assert sample_log.geo_country == "Local Network"
    assert sample_log.user_agent == "System Agent"
