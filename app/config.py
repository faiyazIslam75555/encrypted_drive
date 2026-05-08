"""
Secure Vault — Application Configuration
==========================================
Centralized configuration for all three services.
"""

import os

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./secure_vault.db")

# ─── 2FA Email Config ───
SENDER_EMAIL = "aunondas@gmail.com"
SENDER_PASSWORD = "akkd piaz mgbl dzxf"  # Your App Password
OTP_EXPIRY_SEC = 120

# ---------------------------------------------------------------------------
# Session / Token
# ---------------------------------------------------------------------------
SESSION_EXPIRY_SECONDS: int = int(os.getenv("SESSION_EXPIRY_SECONDS", "3600"))

# ---------------------------------------------------------------------------
# SMTP (for Role 2 — OTP emails)
# ---------------------------------------------------------------------------
SMTP_HOST: str = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "1025"))
SMTP_FROM: str = os.getenv("SMTP_FROM", "noreply@securevault.local")

# ---------------------------------------------------------------------------
# Mock Mode — Set to True to run services independently during development
# When True, cross-service crypto calls return dummy values.
# ---------------------------------------------------------------------------
USE_MOCKS: bool = os.getenv("USE_MOCKS", "false").lower() == "true"

# ---------------------------------------------------------------------------
# RSA Key Size (bits per prime)
# ---------------------------------------------------------------------------
RSA_PRIME_BITS: int = int(os.getenv("RSA_PRIME_BITS", "256"))
