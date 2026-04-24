"""
================================================================
Role 2 — Access Service: OTP Router (Login Step 2)
================================================================
Endpoints
---------
* POST /login/step2  — validate OTP, issue custom session token.

Also exposes a helper ``_trigger_otp()`` used by Role 1's
``/login/step1`` endpoint after password verification.
"""

import random
import smtplib
from email.mime.text import MIMEText

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.config import SMTP_HOST, SMTP_PORT, SMTP_FROM
from app.dependencies import create_session_token

router = APIRouter(tags=["Access Service (Role 2)"])

# =====================================================================
#  IN-MEMORY OTP STORE  (user_id → otp_code)
# =====================================================================
_otp_store: dict[int, str] = {}

# =====================================================================
#  OTP GENERATION & EMAIL
# =====================================================================

def _generate_otp() -> str:
    """Generate a 6-digit numeric OTP."""
    return "".join(str(random.randint(0, 9)) for _ in range(6))


def _send_otp_email(recipient: str, otp: str) -> None:
    """
    Send the OTP via SMTP.

    Falls back to console logging if the SMTP server is
    unreachable (typical in local development).
    """
    msg = MIMEText(f"Your Secure Vault OTP code is: {otp}")
    msg["Subject"] = "Secure Vault — One-Time Password"
    msg["From"]    = SMTP_FROM
    msg["To"]      = recipient

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=5) as srv:
            srv.send_message(msg)
    except Exception:
        # Dev fallback — print to server console
        print(f"[DEV-OTP] user={recipient}  otp={otp}")


def _trigger_otp(user_id: int, email: str) -> None:
    """
    Generate and send an OTP for the given user.

    Called by Role 1's ``/login/step1`` after password verification.
    """
    otp = _generate_otp()
    _otp_store[user_id] = otp
    _send_otp_email(email, otp)

# =====================================================================
#  REQUEST / RESPONSE SCHEMAS
# =====================================================================

class LoginStep2Request(BaseModel):
    user_id: int
    otp_code: str


class LoginStep2Response(BaseModel):
    token: str
    message: str

# =====================================================================
#  POST /login/step2
# =====================================================================

@router.post("/login/step2", response_model=LoginStep2Response)
def login_step2(body: LoginStep2Request):
    """
    Step 2 of 2-factor login — OTP verification.

    If the OTP is valid, a custom JWT-style session token is issued.
    """
    stored_otp = _otp_store.get(body.user_id)

    if stored_otp is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No OTP pending for this user. Call /login/step1 first.",
        )

    if body.otp_code != stored_otp:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid OTP code.",
        )

    # OTP is single-use
    del _otp_store[body.user_id]

    token = create_session_token(body.user_id)
    return LoginStep2Response(
        token=token,
        message="Login successful. Use this token in the Authorization header.",
    )
