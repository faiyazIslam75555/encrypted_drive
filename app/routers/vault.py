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

router = APIRouter(tags=["Hybrid Vault Service (Role 3)"])

@router.post("/vault/upload")
async def upload_file(
    ecc_private_key: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Derive keys from master ECC key
    keys = derive_full_key_package(ecc_private_key)
    
    file_bytes = await file.read()
    
    # 1. Strictly Asymmetric Encryption (No AES/Symmetric)
    encrypted_payload = encrypt_file_asymmetric(file_bytes, keys["rsa_pub"])
    
    # 2. MAC + Signature
    mac, sig = secure_sign_and_mac(file_bytes, keys["ecc_priv"])
    
    # 3. Encrypted Filename
    enc_filename = encrypt_string_asymmetric(file.filename, keys["rsa_pub"])
    
    vault_entry = Vault(
        owner_id=1, 
        filename_encrypted=enc_filename,
        encrypted_payload=encrypted_payload,
        digital_signature=json.dumps({"r": hex(sig[0]), "s": hex(sig[1])}),
        mac_hash=mac,
        uploaded_at=datetime.datetime.utcnow().isoformat()
    )
    db.add(vault_entry)
    db.commit()
    
    return {"message": "File secured", "vault_id": vault_entry.id}

@router.get("/vault/download/{vault_id}")
async def download_file(
    vault_id: int,
    ecc_private_key: str,
    db: Session = Depends(get_db)
):
    keys = derive_full_key_package(ecc_private_key)
    entry = db.query(Vault).filter(Vault.id == vault_id).first()
    if not entry: raise HTTPException(status_code=404)
    
    # Decrypt File & Filename
    try:
        decrypted_bytes = decrypt_file_asymmetric(entry.encrypted_payload, keys["rsa_priv"])
        decrypted_filename = decrypt_string_asymmetric(entry.filename_encrypted, keys["rsa_priv"])
    except Exception as e:
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid Master Key.")
    
    return {
        "filename": decrypted_filename, 
        "data_hex": decrypted_bytes.hex()
    }

@router.get("/vault/list")
def list_vaults(db: Session = Depends(get_db)):
    vaults = db.query(Vault).all()
    return {"entries": [{"id": v.id, "uploaded_at": v.uploaded_at, "signature": v.digital_signature} for v in vaults]}

@router.post("/vault/reset")
def secure_reset(ecc_private_key: str, db: Session = Depends(get_db)):
    """
    "Secure Reset" option that deletes all stored encrypted data.
    """
    # Logic: Delete all vaults
    db.query(Vault).delete()
    db.commit()
    return {"message": "Secure reset complete. All encrypted data has been permanently deleted."}
