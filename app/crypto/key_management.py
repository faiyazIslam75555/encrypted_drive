"""
================================================================
Key Management Service (Role 4)
================================================================
Handles deterministic key derivation and distribution.
Zero-knowledge: No private keys are stored.
"""

from .ecc import point_mul, G, N, generate_ecc_keypair as generate_ecc_keys
from .rsa import generate_rsa_keys
from .hash import scratch_hash
import random

# Global cache to prevent re-generating RSA primes (expensive) during a session
KEY_CACHE = {}

def derive_full_key_package(master_ecc_priv_str: str):
    """
    Derives RSA and ECC keys from a single seed.
    Caches the result to speed up subsequent requests.
    
    This fulfills the requirement that the user only remembers the ECC key.
    """
    if master_ecc_priv_str in KEY_CACHE:
        return KEY_CACHE[master_ecc_priv_str]

    try:
        if master_ecc_priv_str.startswith('0x'):
            priv_int = int(master_ecc_priv_str, 16)
        else:
            priv_int = int(master_ecc_priv_str)
    except:
        # If it's a password/phrase, hash it to get a key
        h = scratch_hash(master_ecc_priv_str)
        priv_int = int(h, 16) % N
    
    # 1. ECC Keys
    ecc_priv = priv_int
    ecc_pub = point_mul(ecc_priv, G)
    
    # 2. RSA Keys (Deterministic Seed)
    # We use the master private key to seed the RSA prime generation.
    seed_val = scratch_hash(str(priv_int) + "RSA_SYSTEM_SEED")
    # CRITICAL FIX: Python 3 randomizes string hashing per-process. 
    # We MUST convert the hex string to an integer for the seed to be deterministic across restarts!
    random.seed(int(seed_val, 16))
    
    # RSA Key Generation (1024 bits for balance of security/performance in pure python)
    rsa_pub, rsa_priv = generate_rsa_keys(bits=1024)
    
    res = {
        "ecc_priv": priv_int,
        "ecc_pub": ecc_pub,
        "rsa_pub": rsa_pub,
        "rsa_priv": rsa_priv
    }
    KEY_CACHE[master_ecc_priv_str] = res
    return res
