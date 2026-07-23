import sqlite3
from flask import Flask, request
import os

app = Flask(__name__)

# Create a fake database with users
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)''')
    c.execute("DELETE FROM users") # Clear old data
    c.execute("INSERT INTO users VALUES (1, 'admin', 'secretpass')")
    c.execute("INSERT INTO users VALUES (2, 'john', 'doe123')")
    conn.commit()
    conn.close()

# The VULNERABLE endpoint
@app.route('/vuln')
def vuln():
    # Get the 'id' from the URL, e.g., ?id=1
    user_id = request.args.get('id')
    
    if user_id is None:
        return "Please provide an id parameter, e.g., ?id=1"

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # ⚠️ DANGER: THIS IS THE SQL INJECTION VULNERABILITY ⚠️
    # We are directly inserting the user input into the SQL query.
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    
    return str(data)

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        init_db()
    app.run(host='0.0.0.0', port=80)