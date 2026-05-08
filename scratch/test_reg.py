import sys
import os

# Add project root to path
sys.path.append('d:\\a study A\\spring 26\\cse 447\\project')

try:
    import json
    import random
    import datetime
    from app.crypto.hash_scratch import scratch_hash
    from app.crypto.rsa_scratch import generate_rsa_keys, encrypt_string
    from app.crypto.ecc_scratch import generate_ecc_keys
    
    print("Testing Registration Logic...")
    
    # 1. Generate Master ECC Key
    ecc_priv, ecc_pub = generate_ecc_keys()
    ecc_priv_str = hex(ecc_priv)
    print(f"ECC Priv: {ecc_priv_str}")
    
    # 2. Derive RSA Keys
    random.seed(scratch_hash(ecc_priv_str))
    rsa_pub, rsa_priv = generate_rsa_keys(bits=1024)
    print(f"RSA Pub: {rsa_pub}")
    
    # 3. Encrypt identity
    username = "testuser"
    email = "test@example.com"
    enc_username = hex(encrypt_string(username, rsa_pub))
    enc_email = hex(encrypt_string(email, rsa_pub))
    print(f"Enc Username: {enc_username}")
    
    # 4. Hash password
    salt = hex(random.getrandbits(64))
    pw_hash = scratch_hash("password123" + salt)
    print(f"PW Hash: {pw_hash}")
    
    print("Success!")
except Exception as e:
    import traceback
    traceback.print_exc()
