import sqlite3

try:
    conn = sqlite3.connect('secure_vault.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM vaults")
    cursor.execute("DELETE FROM share_requests")
    cursor.execute("DELETE FROM shared_files")
    conn.commit()
    conn.close()
    print("DATABASE COMPLETELY WIPED.")
except Exception as e:
    print(f"Error wiping database: {e}")
