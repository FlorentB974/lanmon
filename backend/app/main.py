from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from .core.config import settings
from .db.database import init_db
from .api.routes import router as api_router
from .api.websocket import router as ws_router, scanner_callback
from .scanner.network_scanner import NetworkScanner

# Global scanner instance
scanner = NetworkScanner(scan_interval=settings.SCAN_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    # Startup
    print(f"🚀 Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    
    # Initialize database
    await init_db()
    print("✅ Database initialized")
    
    # Register WebSocket callback for scanner events
    scanner.register_callback(scanner_callback)
    
    # Start background scanning
    await scanner.start_background_scanning()
    print(f"✅ Background scanning started (interval: {settings.SCAN_INTERVAL}s)")
    
    yield
    
    # Shutdown
    print("🛑 Shutting down...")
    await scanner.stop_background_scanning()
    scanner.unregister_callback(scanner_callback)


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Network device monitoring application",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(api_router, prefix="/api", tags=["API"])
app.include_router(ws_router, tags=["WebSocket"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "scanner_running": scanner._running
    }
