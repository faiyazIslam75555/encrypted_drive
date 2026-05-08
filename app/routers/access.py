from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Vault
from app.dependencies import get_current_user
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
    
    if datetime.datetime.utcnow() > user.otp_expiry:
        print(f"[AUTH ERROR] OTP EXPIRED for user {user.display_name}. Code was {user.otp_code}")
        user.otp_code = None
        db.commit()
        raise HTTPException(status_code=401, detail="Your OTP has expired. Please go back and request a new one.")

    if otp != user.otp_code:
        print(f"[AUTH ERROR] OTP MISMATCH for user {user.display_name}. Expected: '{user.otp_code}', Received: '{otp}'")
        raise HTTPException(status_code=401, detail="Incorrect OTP code. Please check your email and try again.")
    
    from app.dependencies import create_session_token
    token = create_session_token(user.id, role=user.role or "user")

    print(f"[AUTH SUCCESS] User {user.id} verified successfully!")
    # Clear OTP after success
    user.otp_code = None
    db.commit()

    from app.dependencies import create_session_token
    token = create_session_token(user.id, role=user.role or "user")

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

@router.post("/profile/update")
def update_profile(display_name: str = Body(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Update Profile: Changes the user's public display name."""
    user = db.query(User).filter(User.id == current_user.id).first()
    user.display_name = display_name
    db.commit()
    return {"message": "Profile updated successfully"}
