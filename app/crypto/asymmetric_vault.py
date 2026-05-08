"""
================================================================
Purely Asymmetric File Encryption (Scratch)
================================================================
Strictly adheres to the requirement: "does not use any symmetric encryption".
Files are encrypted by chunking and applying RSA/ECC directly.
"""

from .rsa import rsa_encrypt, rsa_decrypt
from .ecc import sign_ecdsa as ecdsa_sign
from .hash import scratch_hash

CHUNK_SIZE = 64 # Small chunks for pure asymmetric encryption

def encrypt_file_asymmetric(file_bytes, rsa_pub_key):
    """
    Encrypts file bytes using RSA chunks. 
    Strictly asymmetric (no AES/Symmetric ciphers used).
    """
    encrypted_chunks = []
    # Process in small chunks because RSA has limits
    for i in range(0, len(file_bytes), CHUNK_SIZE):
        chunk = file_bytes[i:i+CHUNK_SIZE]
        m = int.from_bytes(chunk, 'big')
        c = rsa_encrypt(m, rsa_pub_key)
        encrypted_chunks.append(str(c))
    
    return "|".join(encrypted_chunks)

def decrypt_file_asymmetric(encrypted_str, rsa_priv_key):
    """Decrypts RSA-chunked data."""
    chunks = encrypted_str.split("|")
    decrypted_bytes = bytearray()
    
    for c_str in chunks:
        c = int(c_str)
        m = rsa_decrypt(c, rsa_priv_key)
        # Convert back to bytes. Assume original chunk was CHUNK_SIZE or less.
        # We need to be careful with byte lengths.
        b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        decrypted_bytes.extend(b)
        
    return bytes(decrypted_bytes)

def secure_sign_and_mac(file_bytes, ecc_priv_key):
    """
    Computes MAC + Signature as per requirement:
    "compute hash -> sign with ECC -> verify and recompute on retrieval"
    """
    file_hash = scratch_hash(file_bytes)
    z = int(file_hash, 16)
    r, s = ecdsa_sign(ecc_priv_key, z)
    return file_hash, (r, s)

def encrypt_string_asymmetric(text, rsa_pub_key):
    """Encrypts a string (like a filename) as a single RSA chunk."""
    m = int.from_bytes(text.encode('utf-8'), 'big')
    c = rsa_encrypt(m, rsa_pub_key)
    return hex(c)

def decrypt_string_asymmetric(hex_str, rsa_priv_key):
    """Decrypts an RSA-encrypted hex string back to a UTF-8 string."""
    c = int(hex_str, 16)
    m = rsa_decrypt(c, rsa_priv_key)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
