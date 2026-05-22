from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.core.database import init_db, get_db, SessionLocal
from app.core.logging import logger
from app.api.v1.endpoints import logs, rules
from app.services.queue_service import start_worker, stop_worker
from app.services.rule_loader import refresh_rules

app = FastAPI(
    title=settings.APP_NAME,
    description="Google-Ready AI-Powered Security Information and Event Management (SIEM) API",
    version="1.0.0",
    debug=settings.DEBUG
)

# Set up CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
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
