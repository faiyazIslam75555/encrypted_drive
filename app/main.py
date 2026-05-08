"""
Secure Notes & Files Vault — FastAPI Application
==================================================
Wires together the three decoupled services:

  • Identity Service  (Role 1)  →  /register, /login/step1
  • Access Service    (Role 2)  →  /login/step2
  • Hybrid Vault      (Role 3)  →  /vault/upload, /vault/download
"""

import pathlib
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.database import engine, Base
from app.routers import auth, access, vault, sharing

# ---------------------------------------------------------------------------
#  Create all tables on startup
# ---------------------------------------------------------------------------
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
#  App factory
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Secure Notes & Files Vault",
    description=(
        "Academic-grade cryptography project simulating a decoupled "
        "micro-service architecture with pure-Python RSA, ECC/ECDSA, "
        "a custom SPN block cipher, and CBC-MAC — all implemented from "
        "scratch with no third-party crypto libraries."
    ),
    version="1.0.0",
)

# ---------------------------------------------------------------------------
#  Register routers
# ---------------------------------------------------------------------------
app.include_router(auth.router)       # Role 1 — Identity
app.include_router(access.router)     # Role 2 — Access / OTP
app.include_router(vault.router)      # Role 3 — Hybrid Vault
app.include_router(sharing.router)    # Neural Sharing

# ---------------------------------------------------------------------------
#  Static files & Frontend
# ---------------------------------------------------------------------------
_static_dir = pathlib.Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


@app.get("/", tags=["Frontend"], include_in_schema=False)
def serve_frontend():
    """Serve the single-page frontend."""
    return FileResponse(str(_static_dir / "index.html"))


@app.get("/health", tags=["Health"])
def health():
    return {
        "service": "Secure Notes & Files Vault",
        "status": "running",
        "docs": "/docs",
    }
