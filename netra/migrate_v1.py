import sqlite3
import os

db_path = "/app/netra.db"
if not os.path.exists(db_path):
    db_path = "netra.db"

print(f"Migrating DB at: {db_path}")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if column exists
    cursor.execute("PRAGMA table_info(scan)")
    columns = [row[1] for row in cursor.fetchall()]

    if "risk_score" not in columns:
        print("Adding 'risk_score' column to 'scan' table...")
        cursor.execute("ALTER TABLE scan ADD COLUMN risk_score INTEGER DEFAULT 0")
        conn.commit()
        print("Migration successful.")
    else:
        print("'risk_score' column already exists.")

    conn.close()
except Exception as e:
    print(f"Migration Failed: {e}")
