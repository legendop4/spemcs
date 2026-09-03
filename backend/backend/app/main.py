"""SPEMCS FastAPI application entry point."""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from backend.app.config import settings
from backend.app.database import engine

# Configure file + console logging
log_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'logs'))
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(log_dir, 'app.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle events."""
    # Startup: verify database connectivity
    try:
        with engine.connect() as conn:
            row = conn.execute(text("SELECT current_database(), current_schema();")).fetchone()
            logger.info(f"Connected to database={row[0]}, schema={row[1]}")
    except Exception as exc:
        logger.exception("Failed to connect to PostgreSQL database")
        raise

    # Create tables if they don't exist (until Alembic is primary)
    from backend.models.base import Base
    Base.metadata.create_all(bind=engine)
    
    # Safe non-destructive column sync for pre-existing tables
    try:
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE exams ADD COLUMN IF NOT EXISTS network_enforcement BOOLEAN NOT NULL DEFAULT FALSE;"))
            conn.execute(text("ALTER TABLE exams ADD COLUMN IF NOT EXISTS vendor_profile_id UUID REFERENCES vendor_profiles(vendor_id);"))
            conn.commit()
    except Exception as exc:
        logger.warning(f"Non-fatal warning during schema sync: {exc}")
        
    logger.info("Database tables verified/created")

    # The login page advertises this account; create it once in the configured
    # PostgreSQL database using the normal bcrypt password hashing mechanism.
    from backend.app.database import SessionLocal
    from backend.seed.seed_demo_admin import ensure_demo_admin
    with SessionLocal() as db:
        ensure_demo_admin(db)
        
        # Populate in-memory active exam and device caches on startup
        from backend.websocket.manager import realtime_manager
        from backend.models.exam import Exam, ExamDevice
        from backend.models.device import Device
        try:
            # First cache all registered devices mapping to their database device_id
            all_devices = db.query(Device).all()
            for d in all_devices:
                dev_id_str = str(d.device_id)
                if d.hardware_uuid:
                    realtime_manager.register_device_id(d.hardware_uuid, dev_id_str)
                if d.device_name:
                    realtime_manager.register_device_id(d.device_name, dev_id_str)
            logger.info(f"Loaded {len(all_devices)} devices into cache on startup")
            
            active_exams = db.query(Exam).filter(Exam.status == "active").all()
            for exam in active_exams:
                devices = (
                    db.query(Device)
                    .join(ExamDevice, ExamDevice.device_id == Device.device_id)
                    .filter(ExamDevice.exam_id == exam.exam_id)
                    .all()
                )
                device_identifiers = []
                for d in devices:
                    if d.hardware_uuid:
                        device_identifiers.append(d.hardware_uuid)
                    if d.device_name:
                        device_identifiers.append(d.device_name)
                realtime_manager.set_exam_active(str(exam.exam_id), device_identifiers)
            logger.info(f"Loaded {len(active_exams)} active exams into cache on startup")
        except Exception as startup_err:
            logger.error(f"Failed to load active exams into cache: {startup_err}")

    logger.info("SPEMCS API startup complete")
    yield
    # Shutdown
    logger.info("SPEMCS API shutting down")


app = FastAPI(
    title="SPEMCS API",
    version="2.0.0",
    description="Secure Proctoring & Endpoint Monitoring Control System",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "app": "SPEMCS API",
        "version": "2.0.0",
        "status": "online"
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "api": "online"
    }


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# --- Router Registration ---
from backend.routes.devices import router as devices_router
from backend.routes.exams import router as exams_router
from backend.routes.exam_devices import router as exam_devices_router
from backend.routes.sessions import router as sessions_router
from backend.routes.events import router as events_router
from backend.routes.alerts import router as alerts_router
from backend.routes.reports import router as reports_router
from backend.routes.dashboard import router as dashboard_router
from backend.routes.labs import router as labs_router
from backend.routes.agent_api import router as agent_router
from backend.routes.health import router as health_router, management_router
from backend.routes.auth import router as auth_router
from backend.routes.audit_logs import router as audit_logs_router
from backend.routes.policies import router as policies_router

app.include_router(devices_router)
app.include_router(exams_router)
app.include_router(exam_devices_router)
app.include_router(sessions_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(reports_router)
app.include_router(dashboard_router)
app.include_router(labs_router)
app.include_router(agent_router)
app.include_router(health_router)
app.include_router(management_router)
app.include_router(auth_router)
app.include_router(audit_logs_router)
app.include_router(policies_router)

from backend.routes.deployment import router as deployment_router
app.include_router(deployment_router)

# WebSocket endpoints
from backend.websocket.agent_ws import router as agent_ws_router
from backend.websocket.dashboard_ws import router as dashboard_ws_router

app.include_router(agent_ws_router)
app.include_router(dashboard_ws_router)

logger.info('Application setup complete')

