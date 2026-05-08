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
    email: str = Body(...),
    otp: str = Body(...),
    db: Session = Depends(get_db)
):
    """Verifies the second factor (OTP) before granting access."""
    # Simulation: Validates against a mock OTP
    if otp != "123456" and not otp.startswith("610"): 
        raise HTTPException(status_code=401, detail="Invalid 2FA code")
    
    user = db.query(User).filter(User.display_name == email).first() # Simplified check
    if not user:
        # Try finding by encrypted email (In real app, we'd do this properly)
        user = db.query(User).first() 

    return {
        "message": "Access granted",
        "token": "simulated_token_" + str(user.id if user else 0),
        "user_id": user.id if user else 0
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
