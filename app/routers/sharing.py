import json, datetime
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, SharedFile, ShareRequest, Vault
from app.dependencies import get_current_user
from app.crypto.asymmetric_vault import (
    encrypt_file_asymmetric, decrypt_file_asymmetric,
    encrypt_string_asymmetric, decrypt_string_asymmetric
)
from app.crypto.key_management import derive_full_key_package
from app.crypto.hash import scratch_hash

router = APIRouter(tags=["Neural Sharing System"])


# ─── Search Users ───
@router.get("/users/search")
def search_users(q: str = "", current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    users = db.query(User).filter(User.id != current_user.id).all()
    return [{"id": u.id, "name": u.display_name, "public_key": u.rsa_public_key} for u in users]


# ─── PHASE 1: Send a Share Request ───
@router.post("/share/request/{receiver_id}")
def send_request(receiver_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Don't allow duplicate pending requests
    existing = db.query(ShareRequest).filter(
        ShareRequest.sender_id == current_user.id,
        ShareRequest.receiver_id == receiver_id,
        ShareRequest.status == "pending"
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="You already sent a request to this user.")

    req = ShareRequest(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        status="pending",
        created_at=datetime.datetime.utcnow().isoformat()
    )
    db.add(req); db.commit()
    return {"message": "Request sent!", "request_id": req.id}


# ─── PHASE 2a: See incoming requests (for User B) ───
@router.get("/share/requests/received")
def get_received(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    reqs = db.query(ShareRequest).filter(
        ShareRequest.receiver_id == current_user.id
    ).all()
    result = []
    for r in reqs:
        sender = db.query(User).filter(User.id == r.sender_id).first()
        result.append({
            "id": r.id, 
            "sender_id": r.sender_id, 
            "sender_name": sender.display_name if sender else "Unknown", 
            "status": r.status,
            "date": r.created_at
        })
    return result


# ─── PHASE 2b: See sent requests (for User A) ───
@router.get("/share/requests/sent")
def get_sent_requests(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    reqs = db.query(ShareRequest).filter(ShareRequest.sender_id == current_user.id).all()
    result = []
    for r in reqs:
        receiver = db.query(User).filter(User.id == r.receiver_id).first()
        result.append({"id": r.id, "receiver_id": r.receiver_id, "receiver_name": receiver.display_name if receiver else "Unknown", "status": r.status})
    return result


# ─── PHASE 2c: Accept a request ───
@router.post("/share/request/accept/{request_id}")
def accept_request(request_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    req = db.query(ShareRequest).filter(ShareRequest.id == request_id, ShareRequest.receiver_id == current_user.id).first()
    if not req: raise HTTPException(status_code=404, detail="Request not found")
    req.status = "accepted"
    db.commit()
    return {"message": "Request accepted!"}


# ─── PHASE 2d: Reject a request ───
@router.post("/share/request/reject/{request_id}")
def reject_request(request_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    req = db.query(ShareRequest).filter(ShareRequest.id == request_id, ShareRequest.receiver_id == current_user.id).first()
    if not req: raise HTTPException(status_code=404, detail="Request not found")
    req.status = "rejected"
    db.commit()
    return {"message": "Request rejected."}


# ─── PHASE 3: Encrypt & Send file (only after acceptance) ───
class SendFileBody(BaseModel):
    request_id: int
    vault_id: int
    ecc_private_key: str
    encryption_type: str = "rsa" # "rsa" or "ecc"

@router.post("/share/send")
def send_file(body: SendFileBody, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    print("\n[CRYPTO-VERIFY] 🛡️  ECDH HYBRID PIPELINE ENGAGED (V2.0-COMMAS) 🛡️\n")
    # Verify the request is accepted
    req = db.query(ShareRequest).filter(
        ShareRequest.id == body.request_id,
        ShareRequest.sender_id == current_user.id,
        ShareRequest.status == "accepted"
    ).first()
    if not req:
        raise HTTPException(status_code=403, detail="No accepted request found. Recipient must accept first.")

    # Get recipient's public key
    recipient = db.query(User).filter(User.id == req.receiver_id).first()
    if not recipient: raise HTTPException(status_code=404, detail="Recipient not found")

    # Prevent duplicate file sends
    already = db.query(SharedFile).filter(
        SharedFile.vault_id == body.vault_id,
        SharedFile.shared_by == current_user.id,
        SharedFile.shared_with == req.receiver_id
    ).first()
    if already: 
        print("ERROR: Already shared this file with this user.")
        raise HTTPException(status_code=400, detail="Already shared this file with this user.")

    # Decrypt sender's file
    sender_keys = derive_full_key_package(body.ecc_private_key)
    entry = db.query(Vault).filter(Vault.id == body.vault_id, Vault.owner_id == current_user.id).first()
    if not entry: raise HTTPException(status_code=404, detail="File not found")

    try:
        from app.crypto.asymmetric_vault import hybrid_decrypt_ecc
        
        # In the Vault, the wrapped AES key is stored in the mac_hash column
        # and the ciphertext is stored in the encrypted_payload column.
        wrapped_key = entry.mac_hash
        ciphertext = entry.encrypted_payload
        
        if wrapped_key and "," in wrapped_key:
            # New Hybrid ECC Format (ECDH)
            plaintext = hybrid_decrypt_ecc(wrapped_key, ciphertext, sender_keys["ecc_priv"])
        else:
            # Legacy RSA Format (Pre-Hybrid Encryption)
            from app.crypto.asymmetric_vault import decrypt_file_asymmetric
            plaintext = decrypt_file_asymmetric(ciphertext, sender_keys["rsa_priv"])
            
        filename = decrypt_string_asymmetric(entry.filename_encrypted, sender_keys["rsa_priv"])
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"ERROR: Failed to decrypt your file: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to decrypt your file: {e}")

    # Compute MAC for data integrity
    mac = scratch_hash(plaintext)

    # Re-encrypt for recipient using secure Hybrid Encryption
    try:
        pub = json.loads(recipient.ecc_public_key)
        recipient_ecc_pub = (int(pub["x"], 16), int(pub["y"], 16))
    except Exception as e:
        print(f"ERROR: Invalid recipient ECC public key. {e}")
        raise HTTPException(status_code=400, detail="Invalid recipient ECC public key.")

    from app.crypto.asymmetric_vault import hybrid_encrypt_ecc
    try:
        wrapped_key, ciphertext = hybrid_encrypt_ecc(plaintext, recipient_ecc_pub)
        enc_payload = f"{wrapped_key}::{ciphertext}"
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"ERROR: Hybrid Encrypt ECC failed. {e}")
        raise HTTPException(status_code=400, detail=f"Hybrid Encrypt ECC failed. {e}")
    
    # Encrypt filename and MAC using recipient's RSA key
    try:
        pub_rsa = json.loads(recipient.rsa_public_key)
        recipient_rsa_pub = tuple(pub_rsa)
    except Exception as e:
        print(f"ERROR: Invalid recipient RSA public key. {e}")
        raise HTTPException(status_code=400, detail="Invalid recipient RSA public key.")

    try:
        enc_filename = encrypt_string_asymmetric(filename, recipient_rsa_pub)
        enc_mac = encrypt_string_asymmetric(mac, recipient_rsa_pub)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"ERROR: Encrypt string failed. {e}")
        raise HTTPException(status_code=400, detail=f"Encrypt string failed. {e}")

    shared = SharedFile(
        vault_id=body.vault_id,
        shared_by=current_user.id,
        shared_with=req.receiver_id,
        filename_encrypted=enc_filename,
        encrypted_payload=enc_payload,
        encrypted_mac=enc_mac,
        created_at=datetime.datetime.utcnow().isoformat()
    )
    db.add(shared)
    req.status = "completed"
    db.commit()
    print("SUCCESS: File encrypted and sent!")
    return {"message": "File encrypted and sent!", "share_id": shared.id}


# ─── Inbox (files received) ───
@router.get("/share/inbox")
def get_inbox(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    shares = db.query(SharedFile).filter(SharedFile.shared_with == current_user.id).order_by(SharedFile.id.desc()).all()
    result = []
    for s in shares:
        sender = db.query(User).filter(User.id == s.shared_by).first()
        result.append({"id": s.id, "from_id": s.shared_by, "from_name": sender.display_name if sender else "Unknown", "vault_id": s.vault_id, "date": s.created_at})
    return result


# ─── Download Shared File ───
@router.get("/share/download/{share_id}")
def download_shared(share_id: int, ecc_private_key: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    share = db.query(SharedFile).filter(SharedFile.id == share_id, SharedFile.shared_with == current_user.id).first()
    if not share: raise HTTPException(status_code=404, detail="Shared file not found")

    keys = derive_full_key_package(ecc_private_key)
    try:
        from app.crypto.asymmetric_vault import hybrid_decrypt_ecc, decrypt_file_asymmetric
        parts = share.encrypted_payload.split("::")
        if len(parts) == 2:
            wrapped_key, ciphertext = parts
            plaintext = hybrid_decrypt_ecc(wrapped_key, ciphertext, keys["ecc_priv"])
        else:
            plaintext = decrypt_file_asymmetric(share.encrypted_payload, keys["rsa_priv"])
            
        filename = decrypt_string_asymmetric(share.filename_encrypted, keys["rsa_priv"])
        expected_mac = decrypt_string_asymmetric(share.encrypted_mac, keys["rsa_priv"])
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")

    if scratch_hash(plaintext) != expected_mac:
        raise HTTPException(status_code=400, detail="INTEGRITY FAILED: File corrupted.")

    return {"filename": filename, "data_hex": plaintext.hex(), "mac_verified": True}
