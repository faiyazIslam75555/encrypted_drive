"""
================================================================
Scratch Cryptography: ECC Implementation
================================================================
"""
import random, json

# SECP256K1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def mod_inv(a, p):
    if a % p == 0: return 0
    return pow(a, p - 2, p) # Small exception for speed, but could use extended_gcd

def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        m = (3 * x1 * x1 + A) * mod_inv(2 * y1, P)
    else:
        m = (y2 - y1) * mod_inv(x2 - x1, P)
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def point_mul(k, p):
    res = None
    base = p
    while k > 0:
        if k % 2 == 1: res = point_add(res, base)
        base = point_add(base, base)
        k //= 2
    return res

# Aliases for compatibility
scalar_multiply = point_mul

def generate_ecc_keypair():
    priv = random.randint(1, N - 1)
    pub = point_mul(priv, G)
    return priv, pub

# ─── ECC ElGamal (Strictly Asymmetric) ───
def ecc_encrypt(m_int: int, pub_point: tuple):
    """
    Encrypts an integer using ECC ElGamal.
    Result is a pair of points (C1, C2).
    C1 = k*G
    C2 = M + k*Pub
    Where M is the message point.
    """
    k = random.randint(1, N - 1)
    C1 = point_mul(k, G)
    
    # Map message to a point (Simplified for this project: M = m_int * G)
    # This allows for easy subtraction during decryption
    M = point_mul(m_int, G)
    
    shared = point_mul(k, pub_point)
    C2 = point_add(M, shared)
    return C1, C2

def ecc_decrypt(c1: tuple, c2: tuple, priv_key: int):
    """
    Decrypts ECC ElGamal.
    M = C2 - priv*C1
    We then solve for m_int (Simplified: we assume m_int is small or known range)
    """
    shared = point_mul(priv_key, c1)
    # Negate shared point: (x, y) -> (x, -y % P)
    neg_shared = (shared[0], (P - shared[1]) % P)
    M = point_add(c2, neg_shared)
    return M

# More aliases
generate_ecc_keys = generate_ecc_keypair

def sign_ecdsa(z, private_key):
    k = random.randint(1, N - 1)
    r_pt = point_mul(k, G)
    r = r_pt[0] % N
    if r == 0: return sign_ecdsa(z, private_key)
    s = (pow(k, N - 2, N) * (z + r * private_key)) % N
    if s == 0: return sign_ecdsa(z, private_key)
    return r, s

def verify_ecdsa(z, sig, public_key):
    r, s = sig
    if not (0 < r < N and 0 < s < N): return False
    w = pow(s, N - 2, N)
    u1 = (z * w) % N
    u2 = (r * w) % N
    p = point_add(point_mul(u1, G), point_mul(u2, public_key))
    if p is None: return False
    return r == p[0] % N

# Custom hash for dependencies compatibility
from .hash import scratch_hash
def custom_data_hash(data_bytes):
    return int(scratch_hash(data_bytes), 16)
