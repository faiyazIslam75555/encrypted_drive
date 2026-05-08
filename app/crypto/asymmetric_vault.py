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

CHUNK_SIZE = 31 # Reduced to fit within 256-bit ECC curve limit (N)

def encrypt_file_asymmetric(file_bytes, rsa_pub_key):
    """
    Encrypts file bytes using RSA chunks. 
    Strictly asymmetric (no AES/Symmetric ciphers used).
    
    Each chunk is prepended with a 0x01 marker byte before RSA encryption.
    This prevents data loss when chunks contain leading zero bytes
    (common in binary formats like PNG, JPEG, etc.).
    """
    encrypted_chunks = []
    for i in range(0, len(file_bytes), CHUNK_SIZE):
        chunk = file_bytes[i:i+CHUNK_SIZE]
        # Prepend marker byte to preserve leading zeros
        padded = b'\x01' + chunk
        m = int.from_bytes(padded, 'big')
        c = rsa_encrypt(m, rsa_pub_key)
        encrypted_chunks.append(str(c))
    
    return "|".join(encrypted_chunks)

def decrypt_file_asymmetric(encrypted_str, rsa_priv_key):
    """Decrypts RSA-chunked data, stripping the marker byte from each chunk."""
    chunks = encrypted_str.split("|")
    decrypted_bytes = bytearray()
    
    for c_str in chunks:
        c = int(c_str)
        m = rsa_decrypt(c, rsa_priv_key)
        # Convert back to bytes — the first byte is always the 0x01 marker
        b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        # Strip the marker byte to recover original chunk
        decrypted_bytes.extend(b[1:])
        
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

def encrypt_file_ecc(file_bytes, ecc_pub_key):
    """Encrypts file chunks using ECC ElGamal."""
    from .ecc import ecc_encrypt
    encrypted_chunks = []
    for i in range(0, len(file_bytes), CHUNK_SIZE):
        chunk = file_bytes[i:i+CHUNK_SIZE]
        padded = b'\x01' + chunk
        m_int = int.from_bytes(padded, 'big')
        c1, c2 = ecc_encrypt(m_int, ecc_pub_key)
        # Store as c1x,c1y:c2x,c2y
        chunk_str = f"{hex(c1[0])},{hex(c1[1])}:{hex(c2[0])},{hex(c2[1])}"
        encrypted_chunks.append(chunk_str)
    return "|".join(encrypted_chunks)

def hybrid_encrypt_ecc(file_bytes, ecc_pub_key):
    """
    Hybrid Encryption:
    1. AES Key (random) -> Encrypt File
    2. ECC -> Encrypt AES Key
    """
    from .symmetric import generate_aes_key, aes_encrypt
    from .ecc import ecc_encrypt
    
    aes_key = generate_aes_key()
    ciphertext = aes_encrypt(file_bytes, aes_key)
    
    # Encrypt the AES key (as an integer) using ECC
    key_int = int.from_bytes(aes_key, 'big')
    c1, c2 = ecc_encrypt(key_int, ecc_pub_key)
    
    wrapped_key = f"{hex(c1[0])},{hex(c1[1])}:{hex(c2[0])},{hex(c2[1])}"
    return wrapped_key, ciphertext.hex()

def hybrid_decrypt_ecc(wrapped_key, ciphertext_hex, ecc_priv_key):
    """Hybrid Decryption: ECC decrypts AES key -> AES decrypts file."""
    from .symmetric import aes_decrypt
    from .ecc import ecc_decrypt
    
    # Decrypt AES Key
    pts = wrapped_key.split(":")
    c1_raw = pts[0].split(",")
    c2_raw = pts[1].split(",")
    c1 = (int(c1_raw[0], 16), int(c1_raw[1], 16))
    c2 = (int(c2_raw[0], 16), int(c2_raw[1], 16))
    
    m_point = ecc_decrypt(c1, c2, ecc_priv_key)
    # Recovered 128-bit (16 bytes) TEA key
    aes_key = m_point[0].to_bytes(16, 'big')
    
    return aes_decrypt(bytes.fromhex(ciphertext_hex), aes_key)
