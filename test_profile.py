import requests
import json
import time

API = "http://127.0.0.1:8000"

def test():
    # 1. Register a new user
    import uuid
    email = f"test_{uuid.uuid4().hex[:8]}@test.com"
    username = "testuser"
    pwd = "password123"
    
    print("Registering...")
    r = requests.post(f"{API}/register", json={"username": username, "password": pwd, "email": email})
    data = r.json()
    if r.status_code != 200:
        print("Register failed:", data)
        return
    ecc_key = data["ecc_private_key"]
    user_id = data["user_id"]
    print("Registered. Key:", ecc_key)
    
    # 2. Login step 1
    print("Login Step 1...")
    r = requests.post(f"{API}/login/step1", json={"email": email, "password": pwd, "ecc_private_key": ecc_key})
    if r.status_code != 200:
        print("Login Step 1 failed:", r.json())
        return
    
    # Fetch OTP from db manually (since we don't have the email)
    import sqlite3
    conn = sqlite3.connect('secure_vault.db')
    cursor = conn.cursor()
    cursor.execute("SELECT otp_code FROM users WHERE id=?", (user_id,))
    otp = cursor.fetchone()[0]
    conn.close()
    
    print("Login Step 2 with OTP:", otp)
    r = requests.post(f"{API}/login/step2", json={"user_id": user_id, "otp": otp})
    if r.status_code != 200:
        print("Login Step 2 failed:", r.json())
        return
    token = r.json()["token"]
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # 3. Test /me
    print("\nTesting /me...")
    r = requests.get(f"{API}/me?ecc_private_key={ecc_key}", headers=headers)
    print("/me status:", r.status_code)
    if r.status_code != 200:
        print("/me error:", r.json())
        
    # 4. Test profile update
    print("\nTesting /profile/update...")
    payload = {
        "username": "newname",
        "phone": "+123456",
        "profile_pic": "data:image/png;base64,...",
        "ecc_private_key": ecc_key
    }
    r = requests.post(f"{API}/profile/update", json=payload, headers=headers)
    print("/profile/update status:", r.status_code)
    if r.status_code != 200:
        print("/profile/update error:", r.json())
        
    # 5. Test /me again
    print("\nTesting /me after update...")
    r = requests.get(f"{API}/me?ecc_private_key={ecc_key}", headers=headers)
    print("/me status after update:", r.status_code)
    if r.status_code != 200:
        print("/me error:", r.json())

test()
