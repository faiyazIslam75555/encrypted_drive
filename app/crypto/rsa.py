"""
=============================================================
Role 1 — Identity Service: RSA Math Engine & Password Hashing
=============================================================
All cryptographic primitives are implemented from scratch using
pure Python integer arithmetic and bitwise operations.

Exports
-------
* generate_rsa_keypair(bits)   → (public_key, private_key)
* encrypt_rsa(plaintext_int, public_key) → ciphertext_int
* decrypt_rsa(ciphertext_int, private_key) → plaintext_int
* encrypt_session_key_with_rsa(symmetric_key, user_public_key_json)
                                            → encrypted_key_str
* custom_password_hash(password, salt)      → hex digest (256-bit)
* generate_salt(length)                     → random ASCII salt
"""

import random
import json

# =====================================================================
#  1.  MILLER–RABIN PRIMALITY TEST
# =====================================================================

def _miller_rabin_witness(a: int, d: int, n: int, r: int) -> bool:
    """Return True if *a* is a Miller–Rabin witness for compositeness."""
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return False
    for _ in range(r - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return False
    return True                     # composite


def is_prime(n: int, k: int = 40) -> bool:
    """Probabilistic primality test (Miller–Rabin, *k* rounds)."""
    if n < 2:
        return False
    # small primes fast-path
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for sp in small_primes:
        if n == sp:
            return True
        if n % sp == 0:
            return False

    # write n-1 as 2^r · d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 2)
        if _miller_rabin_witness(a, d, n, r):
            return False
    return True


def generate_prime(bits: int = 512) -> int:
    """Generate a random prime of *bits* length."""
    while True:
        # ensure the top bit and bottom bit are set
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate

# =====================================================================
#  2.  EXTENDED EUCLIDEAN ALGORITHM & MODULAR INVERSE
# =====================================================================

def extended_gcd(a: int, b: int):
    """Return (gcd, x, y) such that a·x + b·y = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e: int, phi: int) -> int:
    """Compute e⁻¹ mod phi using the Extended Euclidean Algorithm."""
    gcd, x, _ = extended_gcd(e % phi, phi)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % phi

# =====================================================================
#  3.  RSA KEY GENERATION
# =====================================================================

def generate_rsa_keypair(bits: int = 512):
    """
    Generate an RSA key pair.

    Parameters
    ----------
    bits : int
        Bit-length of each prime factor (the modulus will be ~2·bits).

    Returns
    -------
    public_key  : tuple (e, n)
    private_key : tuple (d, n)
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:                   # ensure p ≠ q
        q = generate_prime(bits)

    n   = p * q
    phi = (p - 1) * (q - 1)
    e   = 65537                     # standard public exponent

    d = mod_inverse(e, phi)
    return (e, n), (d, n)

# =====================================================================
#  4.  RSA ENCRYPT / DECRYPT  (textbook — deterministic)
# =====================================================================

def encrypt_rsa(plaintext_int: int, public_key: tuple) -> int:
    """
    Encrypt an integer with the RSA public key.

    Uses textbook RSA:  c = m^e mod n
    The plaintext integer MUST be in [0, n).
    """
    e, n = public_key
    if plaintext_int < 0 or plaintext_int >= n:
        raise ValueError("Plaintext integer out of range [0, n)")
    return pow(plaintext_int, e, n)


def decrypt_rsa(ciphertext_int: int, private_key: tuple) -> int:
    """
    Decrypt an integer with the RSA private key.

    Uses textbook RSA:  m = c^d mod n
    """
    d, n = private_key
    return pow(ciphertext_int, d, n)

# =====================================================================
#  5.  HELPER — bytes ↔ int conversion
# =====================================================================

def bytes_to_int(b: bytes) -> int:
    """Big-endian bytes → int."""
    result = 0
    for byte in b:
        result = (result << 8) | byte
    return result


def int_to_bytes(n: int) -> bytes:
    """Int → big-endian bytes (minimum length)."""
    if n == 0:
        return b"\x00"
    byte_list = []
    while n > 0:
        byte_list.append(n & 0xFF)
        n >>= 8
    return bytes(reversed(byte_list))

# =====================================================================
#  6.  ENCRYPT / DECRYPT STRINGS VIA RSA
# =====================================================================

def encrypt_string_rsa(plaintext: str, public_key: tuple) -> str:
    """Encrypt a UTF-8 string → hex ciphertext string."""
    m = bytes_to_int(plaintext.encode("utf-8"))
    c = encrypt_rsa(m, public_key)
    return hex(c)


def decrypt_string_rsa(ciphertext_hex: str, private_key: tuple) -> str:
    """Decrypt a hex ciphertext → original UTF-8 string."""
    c = int(ciphertext_hex, 16)
    m = decrypt_rsa(c, private_key)
    return int_to_bytes(m).decode("utf-8")

# =====================================================================
#  7.  OUTPUT BOUNDARY — encrypt_session_key_with_rsa
#      (Integration point for Role 3)
# =====================================================================

def encrypt_session_key_with_rsa(symmetric_key: int,
                                  user_public_key_json: str) -> str:
    """
    Encrypt a symmetric session key (64-bit integer) with the
    user's RSA public key.

    Parameters
    ----------
    symmetric_key       : int   — the 64-bit AES-like session key.
    user_public_key_json: str   — JSON '{"e": ..., "n": ...}'.

    Returns
    -------
    str — hex-encoded RSA ciphertext of the symmetric key.
    """
    pk = json.loads(user_public_key_json)
    public_key = (pk["e"], pk["n"])
    ciphertext = encrypt_rsa(symmetric_key, public_key)
    return hex(ciphertext)


def decrypt_session_key_with_rsa(encrypted_key_hex: str,
                                  private_key_tuple: tuple) -> int:
    """
    Decrypt an RSA-encrypted symmetric session key.

    Parameters
    ----------
    encrypted_key_hex : str          — hex ciphertext from
                                       encrypt_session_key_with_rsa.
    private_key_tuple : (int, int)   — (d, n).

    Returns
    -------
    int — the recovered 64-bit symmetric key.
    """
    ciphertext = int(encrypted_key_hex, 16)
    return decrypt_rsa(ciphertext, private_key_tuple)

# =====================================================================
#  8.  CUSTOM PASSWORD HASH
#      Iterative bit-shifting & XOR — NOT SHA-256
# =====================================================================

_HASH_INIT = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

_MIX_CONSTANTS = [
    0x85EBCA6B, 0xC2B2AE35, 0x27D4EB2F, 0x165667B1,
    0xE6546B64, 0xD34D34D3, 0xABCDEF01, 0x13579BDF,
]


def _rotl32(value: int, shift: int) -> int:
    """32-bit left rotation."""
    return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF


def custom_password_hash(password: str, salt: str) -> str:
    """
    Produce a 256-bit (64-hex-char) password digest using iterative
    bit-shifting and XOR operations.

    Parameters
    ----------
    password : str
    salt     : str

    Returns
    -------
    str — 64 hex characters.
    """
    data = (password + salt).encode("utf-8")

    # ---- initialise 8 × 32-bit lanes ----
    h = list(_HASH_INIT)

    # ---- absorption: fold every data byte into the lanes ----
    for i, byte_val in enumerate(data):
        lane = i % 8
        h[lane] ^= byte_val << ((i % 4) * 8)
        h[lane] = _rotl32(h[lane], 5)
        h[lane] = (h[lane] ^ h[(lane + 1) % 8]) & 0xFFFFFFFF
        h[lane] = (h[lane] * _MIX_CONSTANTS[lane] + i) & 0xFFFFFFFF

    # ---- diffusion: 10 000 rounds of cross-lane mixing ----
    for rnd in range(10_000):
        for lane in range(8):
            h[lane] ^= _rotl32(h[(lane + 1) % 8], 13)
            h[lane] ^= (h[lane] >> 17)
            h[lane] = (h[lane] ^ _rotl32(h[lane], 5)) & 0xFFFFFFFF
            h[lane] = (h[lane] + h[(lane + 3) % 8] + rnd) & 0xFFFFFFFF

    return "".join(format(x, "08x") for x in h)

# =====================================================================
#  9.  SALT GENERATION
# =====================================================================

def generate_salt(length: int = 32) -> str:
    """Generate a random alphanumeric salt string."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(alphabet) for _ in range(length))
