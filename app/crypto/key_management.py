"""
================================================================
Key Management Module
================================================================
Responsible for:
  • Generating ECC key pairs for users.
  • Deriving RSA key pairs deterministically from ECC private keys.
  • Key recovery: given an ECC private key, regenerate both key pairs.
  • Public key serialisation for storage / distribution.

Private keys are NEVER stored on the server.
"""

import json

from app.crypto.ecc import (
    generate_ecc_keypair,
    serialize_ecc_public_key,
    scalar_multiply,
    G,
)
from app.crypto.rsa import (
    derive_rsa_keypair_from_seed,
)


def generate_user_keys():
    """
    Generate a complete set of user keys.

    Returns
    -------
    dict with:
      ecc_private_key : int   — user must download and keep this
      ecc_public_key  : (x, y)
      rsa_public_key  : (e, n)
      rsa_private_key : (d, n) — returned once, never stored
    """
    ecc_priv, ecc_pub = generate_ecc_keypair()
    rsa_pub, rsa_priv = derive_rsa_keypair_from_seed(ecc_priv)

    return {
        "ecc_private_key": ecc_priv,
        "ecc_public_key": ecc_pub,
        "rsa_public_key": rsa_pub,
        "rsa_private_key": rsa_priv,
    }


def recover_keys_from_ecc(ecc_private_key: int):
    """
    Recover all key pairs from the ECC private key.

    This is the core of the "single key to remember" design:
    the RSA key pair is deterministically derived from the ECC key.

    Parameters
    ----------
    ecc_private_key : int

    Returns
    -------
    dict with:
      ecc_public_key  : (x, y)
      rsa_public_key  : (e, n)
      rsa_private_key : (d, n)
    """
    ecc_pub = scalar_multiply(ecc_private_key, G)
    rsa_pub, rsa_priv = derive_rsa_keypair_from_seed(ecc_private_key)

    return {
        "ecc_public_key": ecc_pub,
        "rsa_public_key": rsa_pub,
        "rsa_private_key": rsa_priv,
    }


def serialize_keys_for_storage(ecc_pub, rsa_pub):
    """
    Serialize public keys for database storage.

    Returns
    -------
    (ecc_pub_json, rsa_pub_json) : (str, str)
    """
    ecc_pub_json = serialize_ecc_public_key(ecc_pub)
    rsa_pub_json = json.dumps({"e": rsa_pub[0], "n": rsa_pub[1]})
    return ecc_pub_json, rsa_pub_json


def serialize_private_keys_for_download(ecc_priv, rsa_priv):
    """
    Serialize private keys for ONE-TIME download by the user.
    After this, private keys are never accessible again from the server.

    Returns
    -------
    (ecc_priv_json, rsa_priv_json) : (str, str)
    """
    ecc_priv_json = json.dumps({"d": ecc_priv})
    rsa_priv_json = json.dumps({"d": rsa_priv[0], "n": rsa_priv[1]})
    return ecc_priv_json, rsa_priv_json
