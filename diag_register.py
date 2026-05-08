import sys
import os
import json
import datetime
import random

# Add project root to path
sys.path.append('d:\\a study A\\spring 26\\cse 447\\project')

try:
    print("1. Loading modules...")
    from app.crypto.hash import scratch_hash
    from app.crypto.rsa import generate_rsa_keys, encrypt_string
    from app.crypto.ecc import generate_ecc_keys, point_mul, G
    from app.models import User
    from app.database import SessionLocal, Base, engine
    
    print("2. Ensuring tables exist...")
    Base.metadata.create_all(bind=engine)
    
    print("3. Starting registration simulation...")
    username = "diag_user"
    password = "diag_password"
    email = "diag@example.com"
    
    # Logic from auth.py:register
    ecc_priv, ecc_pub = generate_ecc_keys()
    ecc_priv_str = hex(ecc_priv)
    print(f"   ECC Priv: {ecc_priv_str}")
    
    random.seed(scratch_hash(ecc_priv_str))
    rsa_pub, rsa_priv = generate_rsa_keys(bits=1024)
    print(f"   RSA Pub: {rsa_pub}")
    
    enc_username = hex(encrypt_string(username, rsa_pub))
    enc_email = hex(encrypt_string(email, rsa_pub))
    print(f"   Enc Identity: {enc_username[:20]}...")
    
    salt = hex(random.getrandbits(64))
    pw_hash = scratch_hash(password + salt)
    print(f"   PW Hash: {pw_hash}")
    
    print("4. Persisting to DB...")
    db = SessionLocal()
    user = User(
        username_encrypted=enc_username,
        email_encrypted=enc_email,
        password_hash=pw_hash,
        salt=salt,
        rsa_public_key=json.dumps(rsa_pub),
        ecc_public_key=json.dumps({"x": hex(ecc_pub[0]), "y": hex(ecc_pub[1])}),
        created_at=datetime.datetime.utcnow().isoformat()
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    print(f"5. Success! User ID: {user.id}")
    db.close()

except Exception as e:
    import traceback
    print("\n--- CRASH DETECTED ---")
    traceback.print_exc()
    sys.exit(1)
