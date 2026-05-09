import requests
import sqlite3

API = "http://127.0.0.1:8000"

def test():
    # Let's find existing users and requests to simulate the send
    conn = sqlite3.connect('secure_vault.db')
    cursor = conn.cursor()
    
    # Get an accepted request
    req = cursor.execute("SELECT id, sender_id, receiver_id FROM share_requests WHERE status='accepted' LIMIT 1").fetchone()
    if not req:
        print("No accepted requests.")
        return
        
    req_id, sender_id, receiver_id = req
    
    # We need the receiver to send the file to the sender.
    # In my logic, sender_id is the one who SENT the request. 
    # receiver_id is the one who OWNS the file and ACCEPTED the request.
    # So receiver_id needs to send the file.
    
    # Let's find a file owned by receiver_id
    vault_file = cursor.execute("SELECT id FROM vaults WHERE owner_id=? LIMIT 1", (receiver_id,)).fetchone()
    if not vault_file:
        print("No files for receiver.")
        return
        
    vault_id = vault_file[0]
    
    # We need the ecc_private_key of receiver_id.
    # Since we can't reverse the hash, we don't have it.
    print("Cannot easily get the ecc_key for the receiver. The user needs to test it.")

test()
