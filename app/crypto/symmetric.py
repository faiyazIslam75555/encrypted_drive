import struct
import os

def generate_aes_key():
    """Generates a random 128-bit key (16 bytes)."""
    return os.urandom(16)

def _tea_encrypt_block(v, k):
    """Encrypts a single 64-bit block using TEA algorithm."""
    v0, v1 = v
    k0, k1, k2, k3 = k
    sum_val = 0
    delta = 0x9e3779b9
    for _ in range(32):
        sum_val = (sum_val + delta) & 0xffffffff
        v0 = (v0 + (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xffffffff
        v1 = (v1 + (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xffffffff
    return v0, v1

def _tea_decrypt_block(v, k):
    """Decrypts a single 64-bit block using TEA algorithm."""
    v0, v1 = v
    k0, k1, k2, k3 = k
    delta = 0x9e3779b9
    sum_val = (delta * 32) & 0xffffffff
    for _ in range(32):
        v1 = (v1 - (((v0 << 4) + k2) ^ (v0 + sum_val) ^ ((v0 >> 5) + k3))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + k0) ^ (v1 + sum_val) ^ ((v1 >> 5) + k1))) & 0xffffffff
        sum_val = (sum_val - delta) & 0xffffffff
    return v0, v1

def aes_encrypt(plaintext: bytes, key: bytes):
    """
    Encrypts data using TEA in CBC mode (Cipher Block Chaining).
    Strictly from scratch.
    """
    # Padding (PKCS7 style)
    pad_len = 8 - (len(plaintext) % 8)
    plaintext += bytes([pad_len] * pad_len)
    
    # Key unpacking
    k = struct.unpack(">4I", key)
    iv = os.urandom(8)
    prev_v0, prev_v1 = struct.unpack(">2I", iv)
    
    ciphertext = bytearray(iv)
    for i in range(0, len(plaintext), 8):
        # XOR with previous block (CBC mode)
        v0, v1 = struct.unpack(">2I", plaintext[i:i+8])
        v0 ^= prev_v0
        v1 ^= prev_v1
        
        # Encrypt
        prev_v0, prev_v1 = _tea_encrypt_block((v0, v1), k)
        ciphertext.extend(struct.pack(">2I", prev_v0, prev_v1))
        
    return bytes(ciphertext)

def aes_decrypt(ciphertext: bytes, key: bytes):
    """Decrypts TEA in CBC mode."""
    k = struct.unpack(">4I", key)
    iv = ciphertext[:8]
    data = ciphertext[8:]
    
    prev_v0, prev_v1 = struct.unpack(">2I", iv)
    plaintext = bytearray()
    
    for i in range(0, len(data), 8):
        v0, v1 = struct.unpack(">2I", data[i:i+8])
        dec_v0, dec_v1 = _tea_decrypt_block((v0, v1), k)
        
        # XOR with previous block (CBC mode)
        plaintext.extend(struct.pack(">2I", dec_v0 ^ prev_v0, dec_v1 ^ prev_v1))
        prev_v0, prev_v1 = v0, v1
        
    # Unpadding
    pad_len = plaintext[-1]
    return bytes(plaintext[:-pad_len])
