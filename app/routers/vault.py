"""
================================================================
Role 3 — Hybrid Vault: Upload & Download Router
================================================================
Orchestrates the hybrid encryption pipeline:

Upload
  1. Generate random 64-bit symmetric session key.
  2. Encrypt payload with the custom SPN cipher (CBC mode).
  3. Encrypt the symmetric key with RSA (Role 1 integration).
  4. Sign the encrypted payload MAC with ECDSA (Role 2 integration).
  5. Persist to DB.

Download
  1. Verify the ECDSA signature (Role 2 integration).
  2. Decrypt the symmetric key with RSA (Role 1 integration).
  3. Decrypt the payload with the custom SPN cipher.
  4. Return the original content.

MOCK INTEGRATION: Each cross-service call has a mock fallback so
the vault can run independently during parallel development.
"""

import json
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User, Vault
from app.dependencies import get_current_user
from app.config import USE_MOCKS

from app.crypto.hybrid import (
    generate_symmetric_key,
    encrypt_payload,
    decrypt_payload,
    compute_mac,
)

# =====================================================================
#  MOCK vs REAL integration functions
# =====================================================================

# ---- Role 1 (RSA) ----
try:
    from app.crypto.rsa import (
        encrypt_session_key_with_rsa,
        decrypt_session_key_with_rsa,
    )
    _RSA_AVAILABLE = True
except ImportError:
    _RSA_AVAILABLE = False


def _mock_encrypt_session_key_with_rsa(sym_key: int, pub_json: str) -> str:
    """Mock: return the key as a hex string without real RSA."""
    return hex(sym_key)


def _mock_decrypt_session_key_with_rsa(enc_hex: str, priv_key: tuple) -> int:
    """Mock: parse hex back to int without real RSA."""
    return int(enc_hex, 16)


# ---- Role 2 (ECC / ECDSA) ----
try:
    from app.crypto.ecc import (
        sign_data_with_ecc,
        verify_ecc_signature,
        custom_data_hash,
    )
    _ECC_AVAILABLE = True
except ImportError:
    _ECC_AVAILABLE = False


def _mock_sign_data_with_ecc(data_hash: int, priv_key: int) -> str:
    """Mock: return a dummy signature JSON."""
    return json.dumps({"r": 12345, "s": 67890})


def _mock_verify_ecc_signature(data_hash: int, sig_json: str, pub_json: str) -> bool:
    """Mock: always returns True."""
    return True


def _mock_custom_data_hash(data: bytes) -> int:
    """Mock: trivial hash."""
    h = 0
    for b in data:
        h = ((h << 5) ^ b ^ (h >> 3)) & ((1 << 256) - 1)
    return h


# ---- Dispatcher: picks real or mock at runtime ----

def _encrypt_sym_key(sym_key: int, pub_json: str) -> str:
    if USE_MOCKS or not _RSA_AVAILABLE:
        return _mock_encrypt_session_key_with_rsa(sym_key, pub_json)
    return encrypt_session_key_with_rsa(sym_key, pub_json)


def _decrypt_sym_key(enc_hex: str, priv_key: tuple) -> int:
    if USE_MOCKS or not _RSA_AVAILABLE:
        return _mock_decrypt_session_key_with_rsa(enc_hex, priv_key)
    return decrypt_session_key_with_rsa(enc_hex, priv_key)


def _sign(data_hash: int, priv_key: int) -> str:
    if USE_MOCKS or not _ECC_AVAILABLE:
        return _mock_sign_data_with_ecc(data_hash, priv_key)
    return sign_data_with_ecc(data_hash, priv_key)


def _verify(data_hash: int, sig_json: str, pub_json: str) -> bool:
    if USE_MOCKS or not _ECC_AVAILABLE:
        return _mock_verify_ecc_signature(data_hash, sig_json, pub_json)
    return verify_ecc_signature(data_hash, sig_json, pub_json)


def _hash_data(data: bytes) -> int:
    if USE_MOCKS or not _ECC_AVAILABLE:
        return _mock_custom_data_hash(data)
    return custom_data_hash(data)

# =====================================================================
#  ROUTER
# =====================================================================

router = APIRouter(prefix="/vault", tags=["Hybrid Vault (Role 3)"])

# =====================================================================
#  POST /vault/upload
# =====================================================================

class UploadResponse(dict):
    """Simple dict-based response (avoids circular Pydantic issues)."""


@router.post("/upload")
async def vault_upload(
    file: UploadFile = File(...),
    ecc_private_key: str = Form("0"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Upload & encrypt a file into the vault.

    Form fields
    -----------
    file            : the file to encrypt.
    ecc_private_key : user's ECC private key (integer as string) for signing.
    """
    # read raw file bytes
    plaintext = await file.read()
    if not plaintext:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Empty file")

    # 1. generate random symmetric session key
    sym_key = generate_symmetric_key()

    # 2. encrypt payload with custom SPN (CBC)
    encrypted_bytes = encrypt_payload(plaintext, sym_key)

    # 3. encrypt symmetric key with user's RSA public key
    encrypted_sym_key_hex = _encrypt_sym_key(sym_key,
                                              current_user.rsa_public_key)

    # 4. compute MAC over encrypted payload, then sign
    mac_value = compute_mac(encrypted_bytes, sym_key)
    data_hash = _hash_data(encrypted_bytes)
    ecc_priv  = int(ecc_private_key)
    signature_json = _sign(data_hash, ecc_priv)

    # 5. persist to DB
    vault_entry = Vault(
        owner_id=current_user.id,
        encrypted_payload=encrypted_bytes,
        encrypted_symmetric_key=encrypted_sym_key_hex,
        digital_signature=signature_json,
    )
    db.add(vault_entry)
    db.commit()
    db.refresh(vault_entry)

    return {
        "vault_id": vault_entry.id,
        "mac": hex(mac_value),
        "message": "File encrypted and stored successfully.",
    }

# =====================================================================
#  GET /vault/download/{vault_id}
# =====================================================================

@router.get("/download/{vault_id}")
def vault_download(
    vault_id: int,
    rsa_private_key_d: str = "",
    rsa_private_key_n: str = "",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Download & decrypt a vault entry.

    Query parameters
    ----------------
    rsa_private_key_d : str — the *d* component of the RSA private key.
    rsa_private_key_n : str — the *n* component of the RSA private key.
    """
    entry = db.query(Vault).filter(
        Vault.id == vault_id,
        Vault.owner_id == current_user.id,
    ).first()

    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="Vault entry not found")

    # 1. verify ECDSA signature
    data_hash = _hash_data(entry.encrypted_payload)
    if not _verify(data_hash, entry.digital_signature,
                   current_user.ecc_public_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Signature verification failed — data may be tampered.",
        )

    # 2. decrypt symmetric key with RSA
    if rsa_private_key_d and rsa_private_key_n:
        priv = (int(rsa_private_key_d), int(rsa_private_key_n))
    else:
        # Fallback: if no private key supplied, use mock path
        priv = (0, 1)   # will run through mock
    sym_key = _decrypt_sym_key(entry.encrypted_symmetric_key, priv)

    # 3. decrypt payload
    try:
        plaintext = decrypt_payload(entry.encrypted_payload, sym_key)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Decryption failed: {exc}",
        )

    from fastapi.responses import Response
    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": "attachment; filename=decrypted_file"},
    )

# =====================================================================
#  GET /vault/list
# =====================================================================

@router.get("/list")
def vault_list(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all vault entries for the authenticated user.
    """
    entries = db.query(Vault).filter(Vault.owner_id == current_user.id).all()
    return {"entries": [{"id": e.id} for e in entries]}
