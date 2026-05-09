import sqlite3

conn = sqlite3.connect("secure_vault.db")
cursor = conn.cursor()


cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
print(cursor.fetchall())


cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()