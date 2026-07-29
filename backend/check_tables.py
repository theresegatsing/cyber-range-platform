import sqlite3

SCANNER_DB = r"C:\Users\gatsi\github\Automated_Vulnerability_Scanner\databases\vulnerability_management.db"

conn = sqlite3.connect(SCANNER_DB)
cursor = conn.cursor()

# Get column names from findings table
cursor.execute("PRAGMA table_info(findings)")
columns = cursor.fetchall()

print("📊 Columns in 'findings' table:")
for col in columns:
    print(f"   - {col[1]} ({col[2]})")

# Show sample data
print("\n📝 Sample data (first 2 rows):")
cursor.execute("SELECT * FROM findings LIMIT 2")
rows = cursor.fetchall()
for row in rows:
    print(row)

conn.close()