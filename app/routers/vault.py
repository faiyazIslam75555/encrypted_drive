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
    ecc_private_key: str = None,
    current_user: User = Depends(get_current_user),
):
    result = {
        "user_id": current_user.id,
        "username": current_user.display_name,
        "role": current_user.role,
        "created_at": current_user.created_at,
    }
    if ecc_private_key:
        try:
            keys = derive_full_key_package(ecc_private_key)
            result["username"] = decrypt_string_asymmetric(current_user.username_encrypted, keys["rsa_priv"])
            result["email"] = decrypt_string_asymmetric(current_user.email_encrypted, keys["rsa_priv"])
            
            if current_user.phone_encrypted:
                result["phone"] = decrypt_string_asymmetric(current_user.phone_encrypted, keys["rsa_priv"])
            
            if current_user.profile_pic_encrypted:
                result["profile_pic"] = decrypt_string_asymmetric(current_user.profile_pic_encrypted, keys["rsa_priv"])
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid Master Key for this account.")
    return result

# ─── Upload ───
@router.post("/vault/upload")
async def upload_file(
    ecc_private_key: str = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # 1. Derive keys and read file
    keys = derive_full_key_package(ecc_private_key)
    file_bytes = await file.read()
    file_size = len(file_bytes)
    
    # 2. Hybrid Encryption: AES for file, ECC to wrap the AES key
    from app.crypto.asymmetric_vault import hybrid_encrypt_ecc
    ecc_pub = (int(keys["ecc_pub"][0]), int(keys["ecc_pub"][1]))
    wrapped_key, ciphertext = hybrid_encrypt_ecc(file_bytes, ecc_pub)
    
    # 3. MAC + Signature
    mac, sig = secure_sign_and_mac(file_bytes, keys["ecc_priv"])
    
    # 4. Encrypted Filename
    enc_filename = encrypt_string_asymmetric(file.filename, keys["rsa_pub"])
    
    vault_entry = Vault(
        owner_id=current_user.id,
        filename_encrypted=enc_filename,
        encrypted_payload=ciphertext,
        digital_signature=json.dumps({"r": hex(sig[0]), "s": hex(sig[1])}),
        mac_hash=wrapped_key,
        file_size=file_size,
        uploaded_at=datetime.datetime.utcnow().isoformat()
    )
    db.add(vault_entry)
    db.commit()
    
    return {"message": "File secured", "vault_id": vault_entry.id, "filename": file.filename}

# ─── List Files ───
@router.get("/vault/list")
def list_files(
    ecc_private_key: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists files for the current user, decrypting filenames if the key is provided."""
    # 🛡️ STRICT VERIFICATION: Prove the key can decrypt your own name first
    if ecc_private_key:
        try:
            keys = derive_full_key_package(ecc_private_key)
            decrypt_string_asymmetric(current_user.username_encrypted, keys["rsa_priv"])
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid Master Key for this account.")
    else:
        raise HTTPException(status_code=401, detail="Master Key required.")

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
        from app.crypto.asymmetric_vault import hybrid_decrypt_ecc
        # The AES ciphertext is in encrypted_payload
        # The Wrapped Key is in mac_hash
        plaintext = hybrid_decrypt_ecc(entry.mac_hash, entry.encrypted_payload, keys["ecc_priv"])
        filename = decrypt_string_asymmetric(entry.filename_encrypted, keys["rsa_priv"])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Hybrid Decryption failed: {str(e)}")
    
    return {
        "filename": filename, 
        "data_hex": plaintext.hex()
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
    db.query(Vault).filter(Vault.owner_id == current_user.id).delete()
    db.commit()
    return {"message": "Secure reset complete."}


