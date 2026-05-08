import sqlite3, os

db_path = r'd:\a study A\spring 26\cse 447\project\secure_vault.db'
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Show all tables
c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = c.fetchall()
print('=== DATABASE TABLES ===')
for t in tables:
    c.execute(f'SELECT COUNT(*) FROM {t[0]}')
    count = c.fetchone()[0]
    print(f'  {t[0]}: {count} rows')

# Show DB size
size = os.path.getsize(db_path)
print(f'\n=== STORAGE INFO ===')
print(f'  Database file: secure_vault.db')
print(f'  Location: D:\\a study A\\spring 26\\cse 447\\project\\')
print(f'  Current size: {size / 1024:.1f} KB ({size / 1048576:.2f} MB)')
print(f'  Max capacity: Limited ONLY by your disk space')
print(f'  File limit: NONE (unlimited)')

print(f'\n=== WHERE IS IT? ===')
print(f'  Everything runs on YOUR computer.')
print(f'  Backend = uvicorn on 127.0.0.1:8000 (localhost)')
print(f'  Database = SQLite file on your D: drive')
print(f'  No cloud. No remote server. No free tier limits.')

conn.close()
