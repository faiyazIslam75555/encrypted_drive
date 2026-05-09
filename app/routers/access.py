from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Vault
from app.dependencies import get_current_user
from pydantic import BaseModel
import json, datetime

router = APIRouter()

# ─── Role 2: Access / OTP (Existing) ───
@router.post("/login/step2")
def login_step2(
    user_id: int = Body(...),
    otp: str = Body(...),
    db: Session = Depends(get_db)
):
    """Verifies the second factor (OTP) before granting access."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        print(f"[AUTH ERROR] User ID {user_id} not found in database!")
        raise HTTPException(status_code=401, detail="User not found")

    if not user.otp_code:
        print(f"[AUTH ERROR] No pending OTP found for user {user.display_name}. Did they start Step 1?")
        raise HTTPException(status_code=401, detail="No pending OTP")
    
    print(f"\n[2FA VERIFY] Checking OTP for User ID: {user.id} ({user.display_name})")
    print(f"  -> Expected: '{user.otp_code}'")
    print(f"  -> Received: '{otp}'")

    if datetime.datetime.utcnow() > user.otp_expiry:
        print(f"❌ [AUTH ERROR] OTP EXPIRED for user {user.display_name}!")
        user.otp_code = None
        db.commit()
        raise HTTPException(status_code=401, detail="Your OTP has expired. Please go back and request a new one.")

    if otp != user.otp_code:
        print(f"❌ [AUTH ERROR] OTP MISMATCH! Codes do not match.")
        raise HTTPException(status_code=401, detail="Incorrect OTP code. Please check your email and try again.")
    
    from app.dependencies import create_session_token
    token = create_session_token(user.id, role=user.role or "user")

    print(f"[AUTH SUCCESS] User {user.id} verified successfully!")
    user.otp_code = None
    db.commit()

    return {
        "message": "Access granted",
        "token": token,
        "user_id": user.id
    }

# ─── Profile / Edit (New Requirements) ───
@router.post("/vault/rename/{id}")
def rename_file(id: int, new_name_encrypted: str = Body(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Edit Post: Renames an encrypted file entry."""
    entry = db.query(Vault).filter(Vault.id == id, Vault.owner_id == current_user.id).first()
    if not entry: raise HTTPException(status_code=404, detail="File not found")
    entry.filename_encrypted = new_name_encrypted
    db.commit()
    return {"message": "File renamed successfully"}

class ProfileUpdate(BaseModel):
    username: str
    phone: str = ""
    profile_pic: str = "" # Base64 string
    ecc_private_key: str

@router.post("/profile/update")
def update_profile(
    body: ProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Updates the user's profile and encrypts the new metadata."""
    from app.crypto.key_management import derive_full_key_package
    from app.crypto.asymmetric_vault import encrypt_string_asymmetric, decrypt_string_asymmetric
    
    try:
        keys = derive_full_key_package(body.ecc_private_key)
        decrypt_string_asymmetric(current_user.email_encrypted, keys["rsa_priv"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Master Key.")

    user = db.query(User).filter(User.id == current_user.id).first()
    user.display_name = body.username 
    user.username_encrypted = encrypt_string_asymmetric(body.username, keys["rsa_pub"])
    user.phone_encrypted = encrypt_string_asymmetric(body.phone, keys["rsa_pub"])
    user.profile_pic_encrypted = encrypt_string_asymmetric(body.profile_pic, keys["rsa_pub"])
    
    db.commit()
    return {"message": "Profile updated and encrypted successfully"}
