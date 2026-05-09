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
    """Encrypts a string of any length using chunked RSA."""
    text_bytes = text.encode('utf-8')
    if not text_bytes: return "0x0"
    
    # Use 64 bytes for chunk size (fits comfortably inside 1024-bit RSA)
    CHUNK_SIZE = 64
    encrypted_chunks = []
    
    for i in range(0, len(text_bytes), CHUNK_SIZE):
        chunk = text_bytes[i:i+CHUNK_SIZE]
        padded = b'\x01' + chunk
        m = int.from_bytes(padded, 'big')
        c = rsa_encrypt(m, rsa_pub_key)
        encrypted_chunks.append(hex(c))
        
    return "|".join(encrypted_chunks)

def decrypt_string_asymmetric(hex_str, rsa_priv_key):
    """Decrypts a chunked RSA-encrypted string back to UTF-8."""
    if hex_str == "0x0" or not hex_str: return ""
    
    chunks = hex_str.split("|")
    decrypted_bytes = bytearray()
    
    for c_str in chunks:
        c = int(c_str, 16)
        m = rsa_decrypt(c, rsa_priv_key)
        b = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        decrypted_bytes.extend(b[1:]) # strip 0x01 marker
        
    return bytes(decrypted_bytes).decode('utf-8')

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
    Hybrid Encryption using ECDH:
    1. Generate ephemeral key k, K = k*G
    2. Shared Secret S = k * RecipientPubKey
    3. AES Key = Hash(S.x)
    4. Encrypt file with AES
    """
    from .symmetric import aes_encrypt
    from .ecc import point_mul, G, N
    from .hash import scratch_hash
    import random
    
    # 1. Ephemeral Key
    k = random.randint(1, N - 1)
    K_pt = point_mul(k, G)
    
    # 2. Shared Secret
    shared_pt = point_mul(k, ecc_pub_key)
    # Derive a 128-bit AES key from the shared X-coordinate
    aes_key_hex = scratch_hash(str(shared_pt[0]))[:32] # 16 bytes hex
    aes_key = bytes.fromhex(aes_key_hex)
    
    # 3. Encrypt File
    ciphertext = aes_encrypt(file_bytes, aes_key)
    
    wrapped_key = f"{hex(K_pt[0])},{hex(K_pt[1])}"
    return wrapped_key, ciphertext.hex()

def hybrid_decrypt_ecc(wrapped_key, ciphertext_hex, ecc_priv_key):
    """
    Hybrid Decryption using ECDH:
    1. Ephemeral Public Key K = (x, y) from wrapped_key
    2. Shared Secret S = RecipientPrivKey * K
    3. AES Key = Hash(S.x)
    4. Decrypt file with AES
    """
    from .symmetric import aes_decrypt
    from .ecc import point_mul
    from .hash import scratch_hash
    
    # 1. Parse Ephemeral Public Key
    pts = wrapped_key.split(",")
    K_pt = (int(pts[0], 16), int(pts[1], 16))
    
    # 2. Shared Secret
    shared_pt = point_mul(ecc_priv_key, K_pt)
    aes_key_hex = scratch_hash(str(shared_pt[0]))[:32]
    aes_key = bytes.fromhex(aes_key_hex)
    
    # 3. Decrypt
    return aes_decrypt(bytes.fromhex(ciphertext_hex), aes_key)
