import sqlite3
import os

db_path = "/app/netra.db"
if not os.path.exists(db_path):
    # Try CWD
    db_path = "netra.db"

print(f"Checking DB at: {db_path}")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    tables = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table';"
    ).fetchall()
    print(f"Tables found: {tables}")
    conn.close()
except Exception as e:
    print(f"Error: {e}")
