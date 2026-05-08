"""
================================================================
Scratch Cryptography: RSA Implementation
================================================================
"""
import random

def power(a, b, m):
    res = 1
    a %= m
    while b > 0:
        if b % 2 == 1:
            res = (res * a) % m
        a = (a * a) % m
        b //= 2
    return res

def is_prime(n, k=5):
    if n < 2: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = power(a, d, n)
        if x == 1 or x == n - 1: continue
        for _ in range(r - 1):
            x = power(x, 2, n)
            if x == n - 1: break
        else: return False
    return True

def generate_prime(bits):
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1
        if is_prime(p): return p

def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1: return None
    return (x % m + m) % m

def generate_rsa_keys(bits=512):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return (e, n), (d, n)

# Aliases for compatibility
generate_rsa_keypair = generate_rsa_keys

def rsa_encrypt(m_int, pub_key):
    e, n = pub_key
    return power(m_int, e, n)

def rsa_decrypt(c_int, priv_key):
    d, n = priv_key
    return power(c_int, d, n)

def encrypt_string(text, pub_key):
    m = int.from_bytes(text.encode('utf-8'), 'big')
    if m >= pub_key[1]: raise ValueError("Message too long")
    return rsa_encrypt(m, pub_key)

# Aliases for compatibility
encrypt_string_rsa = encrypt_string
encrypt_rsa = rsa_encrypt
decrypt_rsa = rsa_decrypt
