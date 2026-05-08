import json, datetime
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.crypto.hash import scratch_hash
from app.crypto.rsa import generate_rsa_keys, encrypt_string
from app.crypto.ecc import generate_ecc_keys, point_mul, G

router = APIRouter(tags=["Identity Service (Role 1)"])

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str

class RegisterResponse(BaseModel):
    user_id: int
    ecc_private_key: str
    message: str

@router.post("/register", response_model=RegisterResponse)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    # 1. Generate Master ECC Key
    ecc_priv, ecc_pub = generate_ecc_keys()
    ecc_priv_str = hex(ecc_priv)
    
    # 2. Derive RSA Keys deterministically from ECC Priv
    # (Simplified for this version: we use a seed from the ECC priv)
    import random
    random.seed(scratch_hash(ecc_priv_str))
    rsa_pub, rsa_priv = generate_rsa_keys(bits=1024)
    
    # 3. Encrypt identity with the generated RSA Public Key
    enc_username = hex(encrypt_string(body.username, rsa_pub))
    enc_email = hex(encrypt_string(body.email, rsa_pub))
    
    # 4. Hash password with scratch hash
    salt = hex(random.getrandbits(64))
    pw_hash = scratch_hash(body.password + salt)
    
    user = User(
        username_encrypted=enc_username,
        email_encrypted=enc_email,
        password_hash=pw_hash,
        salt=salt,
        rsa_public_key=json.dumps(rsa_pub),
        ecc_public_key=json.dumps({"x": hex(ecc_pub[0]), "y": hex(ecc_pub[1])}),
        created_at=datetime.datetime.utcnow().isoformat()
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return RegisterResponse(
        user_id=user.id,
        ecc_private_key=ecc_priv_str,
        message="Registration successful. Remember your ECC Private Key; it is the only way to recover your vault."
    )

class LoginStep1Request(BaseModel):
    email: str
    password: str

@router.post("/login/step1")
def login_step1(body: LoginStep1Request, db: Session = Depends(get_db)):
    # Since username/email are RSA-encrypted (deterministic here for search), 
    # we need to find the user.
    users = db.query(User).all()
    matched_user = None
    
    for u in users:
        rsa_pub = tuple(json.loads(u.rsa_public_key))
        try:
            cand_enc_email = hex(encrypt_string(body.email, rsa_pub))
            if cand_enc_email == u.email_encrypted:
                matched_user = u
                break
        except: continue
        
    if not matched_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    # Verify password
    if scratch_hash(body.password + matched_user.salt) != matched_user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
        
    # Trigger 2FA (Simplified: always 123456 for this demo, or use scratch_hash)
    from app.routers.access import _trigger_otp
    _trigger_otp(matched_user.id, body.email)
    
    return {"user_id": matched_user.id, "message": "Verification phase 1 complete. Enter OTP."}
