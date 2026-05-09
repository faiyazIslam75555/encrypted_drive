import json, datetime, random
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.crypto.hash import scratch_hash
from app.crypto.ecc import generate_ecc_keys
from app.crypto.key_management import derive_full_key_package
from app.crypto.asymmetric_vault import encrypt_string_asymmetric, decrypt_string_asymmetric

router = APIRouter(tags=["Identity Service (Role 1)"])

# ─── Models ───
class RegisterRequest(BaseModel):
    username: str
    password: str
    email: str

class RegisterResponse(BaseModel):
    user_id: int
    ecc_private_key: str
    message: str

class LoginStep1Request(BaseModel):
    email: str
    password: str
    ecc_private_key: str

# ─── Register ───
@router.post("/register", response_model=RegisterResponse)
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    # 1. Generate Master ECC Key
    ecc_priv, ecc_pub = generate_ecc_keys()
    ecc_priv_str = hex(ecc_priv)
    
    # 2. Derive RSA Keys from ECC
    keys = derive_full_key_package(ecc_priv_str)
    
    # 3. Hash password
    salt = hex(random.getrandbits(64))
    pw_hash = scratch_hash(body.password + salt)
    
    # 4. Encrypt identity — ONE method used everywhere
    enc_username = encrypt_string_asymmetric(body.username, keys["rsa_pub"])
    enc_email = encrypt_string_asymmetric(body.email, keys["rsa_pub"])
    
    new_user = User(
        display_name=body.username,
        username_encrypted=enc_username,
        email_encrypted=enc_email,
        password_hash=pw_hash,
        salt=salt,
        rsa_public_key=json.dumps(keys["rsa_pub"]),
        ecc_public_key=json.dumps({"x": hex(ecc_pub[0]), "y": hex(ecc_pub[1])}),
        created_at=datetime.datetime.utcnow().isoformat()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return RegisterResponse(
        user_id=new_user.id,
        ecc_private_key=ecc_priv_str,
        message="Registration successful. Save your Master Key!"
    )

# ─── Login Step 1 ───
@router.post("/login/step1")
def login_step1(body: LoginStep1Request, db: Session = Depends(get_db)):
    users = db.query(User).all()
    matched_user = None
    
    # Search: re-encrypt email with each user's public key and compare
    for u in users:
        try:
            rsa_pub = tuple(json.loads(u.rsa_public_key))
            candidate = encrypt_string_asymmetric(body.email, rsa_pub)
            if candidate == u.email_encrypted:
                matched_user = u
                break
        except Exception:
            continue
    
    if not matched_user:
        raise HTTPException(status_code=401, detail="User not found or password incorrect.")

    # Verify Password
    pw_hash = scratch_hash(body.password + matched_user.salt)
    if pw_hash != matched_user.password_hash:
        raise HTTPException(status_code=401, detail="User not found or password incorrect.")
    
    # Verify Master Key
    try:
        keys = derive_full_key_package(body.ecc_private_key)
        decrypted_email = decrypt_string_asymmetric(matched_user.email_encrypted, keys["rsa_priv"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Master Key for this account.")
    
    # Generate OTP
    otp = str(random.randint(100000, 999999))
    matched_user.otp_code = otp
    matched_user.otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
    db.commit()

    print(f"\n[OTP] Code: {otp} for user {matched_user.display_name}")

    # Send OTP email
    try:
        from app.crypto.mail import send_otp_email
        send_otp_email(decrypted_email, otp)
        print(f"  [+] [2FA] OTP sent to {decrypted_email}")
    except Exception as e:
        print(f"  [!] [2FA] Email failed ({e}), use the OTP printed above.")

    return {
        "message": "OTP sent to your email", 
        "email_preview": matched_user.display_name,
        "user_id": matched_user.id
    }
