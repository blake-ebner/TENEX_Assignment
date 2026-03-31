# ---------------------------------------------------------------------------
# main.py
# Entry point for the FastAPI application.
# Handles app setup, CORS configuration, and router registration.
# ---------------------------------------------------------------------------

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from database import engine, Base
from routers import auth, upload, analyze

# Create all database tables on startup (if they don't already exist)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="TENEX_Assignment - Log Analyzer")

# ---------------------------------------------------------------------------
# CORS Middleware
# Allows the Next.js frontend (running on port 3000) to make requests to
# this backend. Without this, the browser would block cross-origin requests.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Routers
# Each router handles a specific group of related endpoints:
#   /auth    -> register and login
#   /api     -> file upload and AI analysis
# ---------------------------------------------------------------------------
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(upload.router, prefix="/api", tags=["upload"])
app.include_router(analyze.router, prefix="/api", tags=["analyze"])


@app.get("/")
def root():
    # Basic sanity check — confirms the API is reachable
    return {"message": "TENEX_Assignment Log Analyzer API is running"}


@app.get("/health")
def health():
    # Health check endpoint — useful for Docker/load balancer readiness probes
    return {"status": "ok"}
