"""
==============================================================
Role 2 — Access Service: Elliptic Curve Math Engine & ECDSA
==============================================================
All ECC primitives are implemented from scratch using pure
Python integer arithmetic.  ECC is used **only** for digital
signatures (ECDSA) — never for data encryption.

Two curve configurations are available (controlled by the
``ECC_CURVE`` environment variable):

  • ``"small"``  (default) — a 64-bit curve suitable for fast
    development and testing on pure-Python math.
  • ``"secp256k1"`` — the production Bitcoin curve (very slow
    in pure Python; expect minutes per key generation).

Exports
-------
* generate_ecc_keypair()     → (private_key_int, public_key_point)
* sign_data_with_ecc(data_hash, private_key)
                             → signature JSON str {"r": ..., "s": ...}
* verify_ecc_signature(data_hash, signature_json, public_key_json)
                             → bool
* serialize_ecc_public_key(point)   → JSON str
* deserialize_ecc_public_key(json)  → (x, y) | None
* custom_data_hash(data_bytes)      → int  (256-bit hash for ECDSA)
"""

import os
import random
import json

# =====================================================================
#  1.  CURVE PARAMETERS
# =====================================================================
#  The "small" curve has PRIME order N=211, which is required for
#  ECDSA to work correctly.  Parameters verified by brute-force
#  order computation and end-to-end sign/verify testing.
#
#  Curve:  y² ≡ x³ + 3x + 7  (mod 1019)
#  Generator G = (1, 101)  — verified on curve
#  Order N = 211           — verified prime
# =====================================================================

_ECC_CURVE = os.getenv("ECC_CURVE", "small")

if _ECC_CURVE == "secp256k1":
    # ---- PRODUCTION: secp256k1 (Bitcoin curve) ----
    P  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    A  = 0
    B  = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
else:
    # ---- DEVELOPMENT: small prime-order elliptic curve ----
    # y² ≡ x³ + 3x + 7  (mod 1019)
    P  = 1019          # prime field
    A  = 3             # curve coefficient a
    B  = 7             # curve coefficient b
    Gx = 1             # generator x
    Gy = 101           # generator y  (101² mod 1019 = 1+3+7 = 11 ✓)
    N  = 211           # order of G  (PRIME — required for ECDSA)

G = (Gx, Gy)
IDENTITY = None                  # point at infinity

# =====================================================================
#  2.  MODULAR ARITHMETIC HELPERS
# =====================================================================

def _extended_gcd(a: int, b: int):
    """Return (gcd, x, y) with a·x + b·y = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def _mod_inverse(a: int, m: int) -> int:
    """Compute a⁻¹ mod m."""
    a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m

# =====================================================================
#  3.  ELLIPTIC CURVE POINT OPERATIONS
# =====================================================================

def point_add(p1, p2):
    """
    Add two points on the active elliptic curve.
    Points are tuples (x, y) or None (identity).
    """
    if p1 is IDENTITY:
        return p2
    if p2 is IDENTITY:
        return p1

    x1, y1 = p1
    x2, y2 = p2

    if x1 == x2 and y1 != y2:
        return IDENTITY

    if x1 == x2 and y1 == y2:
        return point_double(p1)

    s = ((y2 - y1) * _mod_inverse(x2 - x1, P)) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def point_double(pt):
    """Double a point on the curve."""
    if pt is IDENTITY:
        return IDENTITY

    x, y = pt
    if y == 0:
        return IDENTITY

    s = ((3 * x * x + A) * _mod_inverse(2 * y, P)) % P
    x3 = (s * s - 2 * x) % P
    y3 = (s * (x - x3) - y) % P
    return (x3, y3)


def scalar_multiply(k: int, point):
    """
    Compute k·P using the double-and-add algorithm.
    """
    result = IDENTITY
    addend = point
    k = k % N
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_double(addend)
        k >>= 1
    return result

# =====================================================================
#  4.  ECC KEY GENERATION
# =====================================================================

def generate_ecc_keypair():
    """
    Generate an ECC key pair on the active curve.

    Returns
    -------
    private_key : int
    public_key  : (int, int)
    """
    private_key = random.randrange(1, N)
    public_key  = scalar_multiply(private_key, G)
    return private_key, public_key

# =====================================================================
#  5.  CUSTOM DATA HASH  (256-bit)
# =====================================================================

_HASH_IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

_MIX_K = [
    0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F, 0x165667B1,
    0xE6546B64, 0xD34D34D3, 0xABCDEF01, 0x13579BDF,
]


def _rotl32(v: int, s: int) -> int:
    return ((v << s) | (v >> (32 - s))) & 0xFFFFFFFF


def custom_data_hash(data: bytes) -> int:
    """
    Produce a 256-bit hash of *data* as a Python int.
    Used as the message digest for ECDSA sign / verify.
    """
    h = list(_HASH_IV)

    for i, bv in enumerate(data):
        lane = i % 8
        h[lane] ^= bv << ((i % 4) * 8)
        h[lane] = _rotl32(h[lane], 5)
        h[lane] = (h[lane] ^ h[(lane + 1) % 8]) & 0xFFFFFFFF
        h[lane] = (h[lane] * _MIX_K[lane] + i) & 0xFFFFFFFF

    for rnd in range(256):
        for lane in range(8):
            h[lane] ^= _rotl32(h[(lane + 1) % 8], 13)
            h[lane] ^= (h[lane] >> 17)
            h[lane] = (h[lane] ^ _rotl32(h[lane], 5)) & 0xFFFFFFFF
            h[lane] = (h[lane] + h[(lane + 3) % 8] + rnd) & 0xFFFFFFFF

    result = 0
    for i, v in enumerate(h):
        result |= v << (32 * i)
    return result

# =====================================================================
#  6.  ECDSA — SIGN
# =====================================================================

def sign_ecdsa(message_hash: int, private_key: int):
    """
    Sign a hash using ECDSA.

    Returns (r, s).
    """
    z = message_hash % N
    while True:
        k     = random.randrange(1, N)
        R_pt  = scalar_multiply(k, G)
        if R_pt is IDENTITY:
            continue
        r = R_pt[0] % N
        if r == 0:
            continue
        try:
            k_inv = _mod_inverse(k, N)
        except ValueError:
            continue                    # k not coprime to N, retry
        s     = (k_inv * (z + r * private_key)) % N
        if s == 0:
            continue
        return (r, s)

# =====================================================================
#  7.  ECDSA — VERIFY
# =====================================================================

def verify_ecdsa(message_hash: int, signature, public_key) -> bool:
    """Verify an ECDSA signature."""
    r, s = signature
    if not (1 <= r < N and 1 <= s < N):
        return False

    z = message_hash % N
    try:
        s_inv = _mod_inverse(s, N)
    except ValueError:
        return False                    # s not invertible → invalid sig
    u1 = (z * s_inv) % N
    u2 = (r * s_inv) % N

    point = point_add(
        scalar_multiply(u1, G),
        scalar_multiply(u2, public_key),
    )

    if point is IDENTITY:
        return False
    return (point[0] % N) == r

# =====================================================================
#  8.  OUTPUT BOUNDARY — clean wrappers for Role 3
# =====================================================================

def sign_data_with_ecc(data_hash: int, private_key: int) -> str:
    """Sign *data_hash* → JSON signature string for Role 3."""
    r, s = sign_ecdsa(data_hash, private_key)
    return json.dumps({"r": r, "s": s})


def verify_ecc_signature(data_hash: int,
                          signature_json: str,
                          public_key_json: str) -> bool:
    """Verify an ECDSA signature from JSON-encoded values."""
    sig = json.loads(signature_json)
    pk  = json.loads(public_key_json)
    signature  = (sig["r"], sig["s"])
    public_key = (pk["x"], pk["y"])
    return verify_ecdsa(data_hash, signature, public_key)

# =====================================================================
#  9.  SERIALIZATION HELPERS
# =====================================================================

def serialize_ecc_public_key(point) -> str:
    if point is IDENTITY:
        return json.dumps({"x": None, "y": None})
    return json.dumps({"x": point[0], "y": point[1]})


def deserialize_ecc_public_key(data: str):
    d = json.loads(data)
    if d["x"] is None:
        return IDENTITY
    return (d["x"], d["y"])
