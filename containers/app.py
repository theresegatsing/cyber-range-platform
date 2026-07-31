import sqlite3
from flask import Flask, request, redirect
import os

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER, username TEXT, password TEXT)''')
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'secretpass')")
    c.execute("INSERT INTO users VALUES (2, 'john', 'doe123')")
    conn.commit()
    conn.close()

@app.route('/')
def home():
    # Auto-redirect to the vulnerable endpoint with id=1
    return redirect('/vuln?id=1')

@app.route('/vuln')
def vuln():
    user_id = request.args.get('id')
    
    # If no id provided, redirect to id=1
    if user_id is None:
        return redirect('/vuln?id=1')
    
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # ⚠️ SQL INJECTION VULNERABILITY
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        data = cursor.fetchall()
        conn.close()
        
        if len(data) >= 2:
            return f"🏴 FLAG-FOUND: You retrieved {len(data)} users! Data: {data}"
        else:
            return str(data)
    except Exception as e:
        return f"SQL Error: {e}"

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        init_db()
    app.run(host='0.0.0.0', port=80)