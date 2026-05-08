import json, datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Vault
from app.crypto.asymmetric_vault import (
    encrypt_file_asymmetric, 
    decrypt_file_asymmetric, 
    secure_sign_and_mac,
    encrypt_string_asymmetric,
    decrypt_string_asymmetric
)
from app.crypto.key_management import derive_full_key_package
from app.dependencies import get_current_user

router = APIRouter(tags=["Hybrid Vault Service (Role 3)"])

# ─── User Profile ───
@router.get("/me")
def get_profile(
    current_user: User = Depends(get_current_user),
):
    return {
        "user_id": current_user.id,
        "role": current_user.role,
        "created_at": current_user.created_at,
    }

# ─── Upload ───
@router.post("/vault/upload")
async def upload_file(
    ecc_private_key: str = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    keys = derive_full_key_package(ecc_private_key)
    
    file_bytes = await file.read()
    file_size = len(file_bytes)
    
    # 1. Strictly Asymmetric Encryption (No AES/Symmetric)
    encrypted_payload = encrypt_file_asymmetric(file_bytes, keys["rsa_pub"])
    
    # 2. MAC + Signature
    mac, sig = secure_sign_and_mac(file_bytes, keys["ecc_priv"])
    
    # 3. Encrypted Filename
    enc_filename = encrypt_string_asymmetric(file.filename, keys["rsa_pub"])
    
    vault_entry = Vault(
        owner_id=current_user.id,
        filename_encrypted=enc_filename,
        encrypted_payload=encrypted_payload,
        digital_signature=json.dumps({"r": hex(sig[0]), "s": hex(sig[1])}),
        mac_hash=mac,
        file_size=file_size,
        uploaded_at=datetime.datetime.utcnow().isoformat()
    )
    db.add(vault_entry)
    db.commit()
    
    return {"message": "File secured", "vault_id": vault_entry.id, "filename": file.filename}

# ─── List Files ───
@router.get("/vault/list")
def list_vaults(
    ecc_private_key: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    vaults = db.query(Vault).filter(Vault.owner_id == current_user.id).order_by(Vault.id.desc()).all()
    entries = []
    
    for v in vaults:
        entry = {
            "id": v.id,
            "uploaded_at": v.uploaded_at,
            "file_size": v.file_size or 0,
        }
        
        if ecc_private_key:
            try:
                keys = derive_full_key_package(ecc_private_key)
                filename = decrypt_string_asymmetric(v.filename_encrypted, keys["rsa_priv"])
                entry["filename"] = filename
            except Exception:
                entry["filename"] = "Encrypted File"
        else:
            entry["filename"] = "Encrypted File"
        
        entries.append(entry)
    
    return {"entries": entries, "total": len(entries)}

# ─── Download / Decrypt ───
@router.get("/vault/download/{vault_id}")
async def download_file(
    vault_id: int,
    ecc_private_key: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    keys = derive_full_key_package(ecc_private_key)
    entry = db.query(Vault).filter(
        Vault.id == vault_id,
        Vault.owner_id == current_user.id
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        decrypted_bytes = decrypt_file_asymmetric(entry.encrypted_payload, keys["rsa_priv"])
        decrypted_filename = decrypt_string_asymmetric(entry.filename_encrypted, keys["rsa_priv"])
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid Master Key.")
    
    return {
        "filename": decrypted_filename, 
        "data_hex": decrypted_bytes.hex()
    }

# ─── Delete File ───
@router.delete("/vault/{vault_id}")
def delete_file(
    vault_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    entry = db.query(Vault).filter(
        Vault.id == vault_id,
        Vault.owner_id == current_user.id
    ).first()
    if not entry:
        raise HTTPException(status_code=404, detail="File not found")
    
    db.delete(entry)
    db.commit()
    return {"message": "File permanently deleted"}

# ─── Secure Reset (Delete All) ───
@router.post("/vault/reset")
def secure_reset(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    "Secure Reset" option that deletes all stored encrypted data for the current user.
    """
    db.query(Vault).filter(Vault.owner_id == current_user.id).delete()
    db.commit()
    return {"message": "Secure reset complete. All your encrypted data has been permanently deleted."}
