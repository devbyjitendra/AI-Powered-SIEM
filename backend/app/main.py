import sys

# Silence Windows-specific ProactorEventLoop connection lost traceback spam (WinError 10054 / 10053)
if sys.platform == 'win32':
    import asyncio
    from asyncio.proactor_events import _ProactorBasePipeTransport
    
    _orig_call_connection_lost = _ProactorBasePipeTransport._call_connection_lost
    
    def _patched_call_connection_lost(self, exc=None):
        try:
            _orig_call_connection_lost(self, exc)
        except (ConnectionResetError, ConnectionAbortedError):
            pass
        except OSError as e:
            if getattr(e, 'winerror', None) in (10054, 10053):
                pass
            else:
                raise

    _ProactorBasePipeTransport._call_connection_lost = _patched_call_connection_lost

from fastapi import FastAPI, Depends, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.core.database import init_db, get_db, SessionLocal
from app.core.logging import logger
from app.api.v1.endpoints import logs, rules, alerts, cases
from app.services.queue_service import start_worker, stop_worker
from app.services.rule_loader import refresh_rules
from app.services.websocket_manager import manager

app = FastAPI(
    title=settings.APP_NAME,
    description="Google-Ready AI-Powered Security Information and Event Management (SIEM) API",
    version="1.0.0",
    debug=settings.DEBUG
)

# Set up CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def on_startup():
    """
    FastAPI startup hook to initialize database schemas, seed detection rules,
    load rules to the in-memory cache registry, and launch the background
    log ingestion queue worker.
    """
    logger.info("Starting up AI-Powered SIEM Backend...")
    
    # Capture main event loop for WebSocket Manager
    import asyncio
    manager.main_loop = asyncio.get_running_loop()
    
    try:
        init_db()
        logger.info("Database initialized and default rules seeded successfully.")
        
        # Load rules into cache memory
        db = SessionLocal()
        try:
            refresh_rules(db)
        finally:
            db.close()
            
    except Exception as e:
        logger.critical(f"Database initialization failed: {e}")
    
    # Start background ingestion consumer queue
    start_worker()

@app.on_event("shutdown")
async def on_shutdown():
    """
    FastAPI shutdown hook to safely drain queues and close background tasks.
    """
    logger.info("Shutting down AI-Powered SIEM Backend...")
    await stop_worker()

# Register routers
app.include_router(logs.router, prefix="/api/v1/logs", tags=["Logs"])
app.include_router(rules.router, prefix="/api/v1/rules", tags=["Rules"])
app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(cases.router, prefix="/api/v1/cases", tags=["Cases"])

@app.get("/")
def read_root():
    return {
        "message": "AI-Powered SIEM API Backend is running",
        "health_check": "/api/v1/health",
        "docs": "/docs"
    }

@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time security alerts streaming.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Maintain connection, handle incoming control messages if any
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")
        manager.disconnect(websocket)

@app.get("/api/v1/health")
def health_check(db: Session = Depends(get_db)):
    """
    Health check endpoint to monitor the status of the API and database connectivity.
    """
    db_status = "healthy"
    try:
        # Perform a simple query to verify database response
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"
        logger.error(f"Database health check failed: {e}")

    return {
        "status": "online",
        "app_name": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "database": db_status
    }
