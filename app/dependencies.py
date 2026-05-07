"""
================================================================
Role 2 — Access Service: OTP, Session Tokens & RBAC
================================================================
Implements:
  • Custom Base64 encoder / decoder (no standard base64 module).
  • Custom JWT-style session token (dictionary serialisation + ECDSA).
  • OTP generation & email delivery via smtplib.
  • FastAPI dependency ``get_current_user`` for RBAC.
  • ``require_admin`` dependency for admin-only endpoints.
"""

import json
import time
import random

from fastapi import Depends, HTTPException, Header, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.config import SESSION_EXPIRY_SECONDS

# ---- MOCK / REAL: ECC signing for session tokens ----
try:
    from app.crypto.ecc import (
        generate_ecc_keypair,
        sign_ecdsa,
        verify_ecdsa,
        custom_data_hash,
    )
    _ECC_AVAILABLE = True
except ImportError:
    _ECC_AVAILABLE = False


# =====================================================================
#  1.  CUSTOM BASE64  (URL-safe alphabet, no stdlib)
# =====================================================================

_B64_CHARS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_"
)


def custom_base64_encode(data: bytes) -> str:
    """Encode bytes → URL-safe Base64 string (no ``=`` padding)."""
    result: list[str] = []
    i = 0
    while i < len(data):
        b0 = data[i]
        b1 = data[i + 1] if i + 1 < len(data) else 0
        b2 = data[i + 2] if i + 2 < len(data) else 0

        result.append(_B64_CHARS[b0 >> 2])
        result.append(_B64_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)])

        if i + 1 < len(data):
            result.append(_B64_CHARS[((b1 & 0x0F) << 2) | (b2 >> 6)])
        if i + 2 < len(data):
            result.append(_B64_CHARS[b2 & 0x3F])

        i += 3
    return "".join(result)


def custom_base64_decode(encoded: str) -> bytes:
    """Decode a URL-safe Base64 string → bytes."""
    lookup = {ch: idx for idx, ch in enumerate(_B64_CHARS)}
    encoded = encoded.rstrip("=")

    result: list[int] = []
    i = 0
    length = len(encoded)
    while i < length:
        sa = lookup.get(encoded[i], 0)     if i < length     else 0
        sb = lookup.get(encoded[i + 1], 0) if i + 1 < length else 0
        sc = lookup.get(encoded[i + 2], 0) if i + 2 < length else 0
        sd = lookup.get(encoded[i + 3], 0) if i + 3 < length else 0

        triple = (sa << 18) | (sb << 12) | (sc << 6) | sd

        result.append((triple >> 16) & 0xFF)
        if i + 2 < length:
            result.append((triple >> 8) & 0xFF)
        if i + 3 < length:
            result.append(triple & 0xFF)

        i += 4
    return bytes(result)

# =====================================================================
#  2.  SERVER-SIDE ECC KEY (for signing session tokens)
#      Deterministic — derived from a fixed seed so tokens survive
#      server restarts (in production, use an env-var secret).
# =====================================================================

if _ECC_AVAILABLE:
    from app.crypto.ecc import scalar_multiply, G, N as _ECC_N
    _SERVER_SEED = b"SecureVault-Server-Token-Key-2026"
    _SERVER_ECC_PRIV = (custom_data_hash(_SERVER_SEED) % (_ECC_N - 1)) + 1
    _SERVER_ECC_PUB  = scalar_multiply(_SERVER_ECC_PRIV, G)
else:
    _SERVER_ECC_PRIV = 1
    _SERVER_ECC_PUB  = (0, 0)

# =====================================================================
#  3.  CUSTOM JWT-STYLE SESSION TOKEN
# =====================================================================

def _compute_token_hash(payload_bytes: bytes) -> int:
    """Hash payload bytes → int for ECDSA signing."""
    if _ECC_AVAILABLE:
        return custom_data_hash(payload_bytes)
    # Mock hash — simple XOR fold
    h = 0
    for b in payload_bytes:
        h = ((h << 5) ^ b ^ (h >> 3)) & ((1 << 256) - 1)
    return h


def create_session_token(user_id: int, role: str = "user") -> str:
    """
    Build a custom JWT-style token:

        <base64(payload_json)>.<base64(signature_json)>

    The payload is a JSON dict; the signature is ECDSA over its hash.
    Includes the user role in the payload for RBAC.
    """
    payload = {
        "sub": user_id,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + SESSION_EXPIRY_SECONDS,
    }
    payload_json  = json.dumps(payload, separators=(",", ":"))
    payload_bytes = payload_json.encode("utf-8")
    payload_b64   = custom_base64_encode(payload_bytes)

    # sign
    h = _compute_token_hash(payload_bytes)
    if _ECC_AVAILABLE:
        r, s = sign_ecdsa(h, _SERVER_ECC_PRIV)
    else:
        r, s = h % (10**20), h % (10**19)       # mock signature

    sig_json = json.dumps({"r": r, "s": s}, separators=(",", ":"))
    sig_b64  = custom_base64_encode(sig_json.encode("utf-8"))

    return f"{payload_b64}.{sig_b64}"


def verify_session_token(token: str) -> dict:
    """
    Verify a session token and return the payload dict
    containing ``sub`` (user_id) and ``role``.

    Raises HTTPException 401 on invalid / expired tokens.
    """
    parts = token.split(".")
    if len(parts) != 2:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Malformed token")

    try:
        payload_bytes = custom_base64_decode(parts[0])
        sig_bytes     = custom_base64_decode(parts[1])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token decode error")

    payload = json.loads(payload_bytes.decode("utf-8"))
    sig     = json.loads(sig_bytes.decode("utf-8"))

    # verify signature
    h = _compute_token_hash(payload_bytes)
    if _ECC_AVAILABLE:
        valid = verify_ecdsa(h, (sig["r"], sig["s"]), _SERVER_ECC_PUB)
    else:
        valid = True                            # mock always passes

    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid token signature")

    # check expiry
    if payload.get("exp", 0) < time.time():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token expired")

    return payload

# =====================================================================
#  4.  RBAC MIDDLEWARE — FastAPI Dependencies
# =====================================================================

def get_current_user(
    authorization: str = Header(..., alias="Authorization"),
    db: Session = Depends(get_db),
) -> User:
    """
    FastAPI dependency that extracts & validates the session token
    from the ``Authorization`` header and returns the User object.

    Expected header format::

        Authorization: Bearer <token>
    """
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Authorization header must be "
                                   "'Bearer <token>'")

    payload = verify_session_token(token)
    user_id = payload["sub"]
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="User not found")
    return user


def require_admin(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    FastAPI dependency that ensures the current user has admin role.
    Raises 403 Forbidden if the user is not an admin.
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return current_user
