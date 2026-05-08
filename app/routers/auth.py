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
    
    # 2. Derive RSA Keys deterministically from ECC Priv using the central service
    from app.crypto.key_management import derive_full_key_package
    keys = derive_full_key_package(ecc_priv_str)
    rsa_pub = keys["rsa_pub"]
    
    # 3. Encrypt identity with the generated RSA Public Key
    enc_username = hex(encrypt_string(body.username, rsa_pub))
    enc_email = hex(encrypt_string(body.email, rsa_pub))
    
    # 4. Hash password with scratch hash
    import random
    salt = hex(random.getrandbits(64))
    pw_hash = scratch_hash(body.password + salt)
    
    user = User(
        display_name=body.username,
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
    ecc_private_key: str

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
        
    # 3. Generate and Send Real OTP
    import random, datetime
    from app.crypto.mail import send_otp_email
    from app.crypto.key_management import derive_full_key_package
    from app.crypto.asymmetric_vault import decrypt_string_asymmetric

    otp = str(random.randint(100000, 999999))
    matched_user.otp_code = otp
    matched_user.otp_expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=2)
    db.commit()

    # CRITICAL: Always print to terminal so you can see it if email fails!
    print(f"\n[!!!] NEW LOGIN OTP: {otp} (User: {matched_user.display_name})\n")

    # Re-derive keys to decrypt the email address
    keys = derive_full_key_package(body.ecc_private_key)
    
    try:
        real_email = decrypt_string_asymmetric(matched_user.email_encrypted, keys["rsa_priv"])
        send_otp_email(real_email, otp)
        print(f"✅ [2FA] OTP sent to {real_email}")
    except UnicodeDecodeError:
        print(f"❌ [AUTH ERROR] Master Key Mismatch for user {matched_user.display_name}!")
        raise HTTPException(status_code=401, detail="Invalid Master Key. Decryption failed.")
    except Exception as e:
        print(f"❌ [2FA ERROR] {e}")
        # If it's just a mail error, we can still let them in if they have the console
        pass

    return {
        "message": "OTP sent to your email", 
        "email_preview": matched_user.display_name,
        "user_id": matched_user.id
    }
