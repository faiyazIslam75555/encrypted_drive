import sqlite3

conn = sqlite3.connect('secure_vault.db')
cursor = conn.cursor()
rows = cursor.execute("SELECT id, mac_hash FROM vaults").fetchall()
for r in rows:
    print(f"ID {r[0]}: length {len(r[1]) if r[1] else 0}, content: {r[1][:80] if r[1] else 'None'}")
