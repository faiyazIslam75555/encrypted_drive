"""
================================================================
Role 1 — Identity Service: Auth Router
================================================================
Endpoints
---------
* POST /register  — create user (RSA keypair, encrypted username,
                     custom password hash, ECC key mock).
* POST /login/step1 — validate custom password hash, return user_id
                       so that Role 2 can proceed with OTP (step2).
"""

import json
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.config import RSA_PRIME_BITS
from app.crypto.rsa import (
    generate_rsa_keypair,
    encrypt_string_rsa,
    custom_password_hash,
    generate_salt,
    bytes_to_int,
    encrypt_rsa,
)

# ---- MOCK: ECC key generation (Role 2 integration) ----
# In fully-integrated mode, replace with real import:
#   from app.crypto.ecc import generate_ecc_keypair, serialize_ecc_public_key
try:
    from app.crypto.ecc import generate_ecc_keypair, serialize_ecc_public_key
    _ECC_AVAILABLE = True
except ImportError:
    _ECC_AVAILABLE = False


def _mock_generate_ecc_keypair():
    """Mock: returns placeholder ECC keys for independent development."""
    return 12345, (0, 0)


def _mock_serialize_ecc_public_key(point):
    return json.dumps({"x": point[0], "y": point[1]})


router = APIRouter(tags=["Identity Service (Role 1)"])

# =====================================================================
#  REQUEST / RESPONSE SCHEMAS
# =====================================================================

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str | None = None        # optional, used for OTP in step2


class RegisterResponse(BaseModel):
    user_id: int
    rsa_public_key: str             # JSON {"e": ..., "n": ...}
    rsa_private_key: str            # JSON {"d": ..., "n": ...} — returned ONCE
    ecc_public_key: str             # JSON {"x": ..., "y": ...}
    ecc_private_key: str            # returned ONCE — never stored
    message: str


class LoginStep1Request(BaseModel):
    username: str
    password: str
    email: str | None = None        # for OTP delivery in step2


class LoginStep1Response(BaseModel):
    user_id: int
    message: str

# =====================================================================
#  POST /register
# =====================================================================

@router.post("/register", response_model=RegisterResponse,
             status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register a new user.

    1. Generate a random salt and hash the password.
    2. Generate an RSA key pair.
    3. Encrypt the username with the RSA public key.
    4. Generate (or mock) an ECC key pair.
    5. Store user in DB.  Private keys are returned but **never** stored.
    """
    # --- password hashing ---
    salt = generate_salt()
    pw_hash = custom_password_hash(body.password, salt)

    # --- RSA key pair ---
    rsa_pub, rsa_priv = generate_rsa_keypair(bits=RSA_PRIME_BITS)
    rsa_pub_json  = json.dumps({"e": rsa_pub[0], "n": rsa_pub[1]})
    rsa_priv_json = json.dumps({"d": rsa_priv[0], "n": rsa_priv[1]})

    # --- Encrypt username with RSA public key (textbook RSA) ---
    encrypted_username = encrypt_string_rsa(body.username, rsa_pub)

    # --- ECC key pair (mock or real) ---
    if _ECC_AVAILABLE:
        ecc_priv, ecc_pub = generate_ecc_keypair()
        ecc_pub_json = serialize_ecc_public_key(ecc_pub)
    else:
        ecc_priv, ecc_pub = _mock_generate_ecc_keypair()
        ecc_pub_json = _mock_serialize_ecc_public_key(ecc_pub)
    ecc_priv_json = json.dumps({"d": ecc_priv})

    # --- persist ---
    user = User(
        username=encrypted_username,
        password_hash=pw_hash,
        salt=salt,
        rsa_public_key=rsa_pub_json,
        ecc_public_key=ecc_pub_json,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return RegisterResponse(
        user_id=user.id,
        rsa_public_key=rsa_pub_json,
        rsa_private_key=rsa_priv_json,
        ecc_public_key=ecc_pub_json,
        ecc_private_key=ecc_priv_json,
        message="Registration successful. Store your private keys securely — "
                "they will NOT be shown again.",
    )

# =====================================================================
#  POST /login/step1
# =====================================================================

@router.post("/login/step1", response_model=LoginStep1Response)
def login_step1(body: LoginStep1Request, db: Session = Depends(get_db)):
    """
    Step 1 of 2-factor login — password verification.

    Because the username is stored as RSA-encrypted ciphertext
    (textbook RSA, deterministic), we locate the user by encrypting
    the submitted username with each user's stored public key and
    comparing with the stored ciphertext.  This is O(n) but
    acceptable for an academic-scale dataset.
    """
    users = db.query(User).all()
    matched_user: User | None = None

    for u in users:
        pk = json.loads(u.rsa_public_key)
        pub_key = (pk["e"], pk["n"])
        candidate_ct = encrypt_string_rsa(body.username, pub_key)
        if candidate_ct == u.username:
            matched_user = u
            break

    if matched_user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password")

    # --- verify password ---
    computed_hash = custom_password_hash(body.password, matched_user.salt)
    if computed_hash != matched_user.password_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password")

    # --- trigger OTP (Role 2 integration) ---
    # Role 2's access router handles OTP generation & email.
    # Here we just confirm the password is valid and surface the
    # user_id for step2.
    #
    # If an email was provided, Role 2 will use it in /login/step2
    # (stored in-memory for the OTP flow — see access.py).
    if body.email:
        from app.routers.access import _trigger_otp
        _trigger_otp(matched_user.id, body.email)

    return LoginStep1Response(
        user_id=matched_user.id,
        message="Password verified. Proceed to /login/step2 with OTP.",
    )
