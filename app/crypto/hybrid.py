"""
================================================================
Role 3 — Hybrid Vault: Custom Symmetric Cipher & CBC-MAC
================================================================
Implements a simplified 64-bit Substitution-Permutation Network
(SPN) block cipher in CBC mode and a CBC-MAC integrity tag.

All operations use pure Python bitwise logic — no standard
AES, DES, ChaCha20, or any library cipher.

Exports
-------
* generate_symmetric_key()                → int (64-bit key)
* encrypt_payload(plaintext_bytes, key)   → bytes (IV ∥ ciphertext)
* decrypt_payload(encrypted_bytes, key)   → bytes (original data)
* compute_mac(data_bytes, key)            → int   (64-bit MAC tag)
"""

import random
import struct

# =====================================================================
#  1.  S-BOX & INVERSE S-BOX  (4-bit, 16 entries)
# =====================================================================

S_BOX = [
    0xE, 0x4, 0xD, 0x1, 0x2, 0xF, 0xB, 0x8,
    0x3, 0xA, 0x6, 0xC, 0x5, 0x9, 0x0, 0x7,
]

S_BOX_INV = [0] * 16
for _i, _v in enumerate(S_BOX):
    S_BOX_INV[_v] = _i

# =====================================================================
#  2.  PERMUTATION TABLE  (64-bit → 64-bit bit shuffle)
# =====================================================================
#  A fixed permutation mapping:  new_pos[i] = (i·17 + 5) mod 64
#  Pre-computed for speed.

_PERM = [(i * 17 + 5) % 64 for i in range(64)]
_PERM_INV = [0] * 64
for _i, _p in enumerate(_PERM):
    _PERM_INV[_p] = _i

# =====================================================================
#  3.  CORE SPN BUILDING BLOCKS
# =====================================================================

MASK64 = 0xFFFFFFFFFFFFFFFF
NUM_ROUNDS = 4


def _substitute(block: int, sbox: list) -> int:
    """Apply a 4-bit S-box to each of the 16 nibbles (64 bits)."""
    result = 0
    for i in range(16):
        nibble = (block >> (4 * i)) & 0xF
        result |= sbox[nibble] << (4 * i)
    return result


def _permute(block: int) -> int:
    """Bit permutation on a 64-bit block."""
    result = 0
    for i in range(64):
        if block & (1 << i):
            result |= 1 << _PERM[i]
    return result


def _permute_inv(block: int) -> int:
    """Inverse bit permutation."""
    result = 0
    for i in range(64):
        if block & (1 << i):
            result |= 1 << _PERM_INV[i]
    return result

# =====================================================================
#  4.  KEY SCHEDULE
# =====================================================================

def _key_schedule(key64: int) -> list:
    """
    Derive NUM_ROUNDS + 1 round keys from a 64-bit master key.
    Uses rotation and XOR mixing.
    """
    keys = [key64 & MASK64]
    for i in range(1, NUM_ROUNDS + 1):
        k = keys[-1]
        k = ((k << 7) | (k >> 57)) & MASK64      # rotate left 7
        k ^= (i * 0x1234567890ABCDEF) & MASK64    # round constant
        k = (k + 0xDEADBEEFCAFE0000) & MASK64     # extra mixing
        keys.append(k)
    return keys

# =====================================================================
#  5.  SINGLE-BLOCK ENCRYPT / DECRYPT
# =====================================================================

def _spn_encrypt_block(block: int, round_keys: list) -> int:
    """Encrypt one 64-bit block through the SPN."""
    state = block & MASK64
    for i in range(NUM_ROUNDS):
        state ^= round_keys[i]
        state = _substitute(state, S_BOX)
        state = _permute(state)
    state ^= round_keys[NUM_ROUNDS]         # final key addition
    return state


def _spn_decrypt_block(block: int, round_keys: list) -> int:
    """Decrypt one 64-bit block through the SPN."""
    state = block & MASK64
    state ^= round_keys[NUM_ROUNDS]
    for i in range(NUM_ROUNDS - 1, -1, -1):
        state = _permute_inv(state)
        state = _substitute(state, S_BOX_INV)
        state ^= round_keys[i]
    return state

# =====================================================================
#  6.  PADDING (PKCS#7-style, 8-byte block boundary)
# =====================================================================

def _pad(data: bytes) -> bytes:
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Corrupted padding")
    return data[:-pad_len]

# =====================================================================
#  7.  BYTES ↔ 64-bit BLOCK CONVERSION
# =====================================================================

def _bytes_to_blocks(data: bytes) -> list:
    return [int.from_bytes(data[i:i + 8], "big") for i in range(0, len(data), 8)]


def _blocks_to_bytes(blocks: list) -> bytes:
    return b"".join(b.to_bytes(8, "big") for b in blocks)

# =====================================================================
#  8.  CBC-MODE ENCRYPTION / DECRYPTION
# =====================================================================

def generate_symmetric_key() -> int:
    """Generate a random 64-bit symmetric key."""
    return random.getrandbits(64)


def encrypt_payload(plaintext_bytes: bytes, key64: int) -> bytes:
    """
    Encrypt arbitrary bytes using the custom SPN in CBC mode.

    Returns
    -------
    bytes — 8-byte IV ∥ ciphertext blocks (each 8 bytes).
    """
    padded    = _pad(plaintext_bytes)
    blocks    = _bytes_to_blocks(padded)
    rk        = _key_schedule(key64)
    iv        = random.getrandbits(64)
    prev      = iv
    encrypted = []

    for block in blocks:
        xored     = (block ^ prev) & MASK64
        enc_block = _spn_encrypt_block(xored, rk)
        encrypted.append(enc_block)
        prev = enc_block

    # serialise: IV (8 bytes) ∥ encrypted blocks
    return iv.to_bytes(8, "big") + _blocks_to_bytes(encrypted)


def decrypt_payload(encrypted_bytes: bytes, key64: int) -> bytes:
    """
    Decrypt a payload produced by encrypt_payload().

    Parameters
    ----------
    encrypted_bytes : bytes — IV ∥ ciphertext.
    key64           : int   — the same 64-bit key used for encryption.

    Returns
    -------
    bytes — original plaintext.
    """
    iv        = int.from_bytes(encrypted_bytes[:8], "big")
    ct_bytes  = encrypted_bytes[8:]
    blocks    = _bytes_to_blocks(ct_bytes)
    rk        = _key_schedule(key64)
    prev      = iv
    decrypted = []

    for block in blocks:
        dec_block = _spn_decrypt_block(block, rk)
        plain     = (dec_block ^ prev) & MASK64
        decrypted.append(plain)
        prev = block

    return _unpad(_blocks_to_bytes(decrypted))

# =====================================================================
#  9.  CBC-MAC  (custom Message Authentication Code)
# =====================================================================

def compute_mac(data_bytes: bytes, key64: int) -> int:
    """
    Compute a 64-bit CBC-MAC over *data_bytes*.

    The tag is produced by encrypting each padded block with the SPN
    in CBC chain, returning the final encrypted block.
    """
    padded = _pad(data_bytes)
    blocks = _bytes_to_blocks(padded)
    rk     = _key_schedule(key64)

    mac = 0                         # start with zero IV for MAC
    for block in blocks:
        mac = _spn_encrypt_block((mac ^ block) & MASK64, rk)

    return mac
