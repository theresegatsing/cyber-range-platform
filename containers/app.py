import sqlite3
from flask import Flask, request, redirect
import os
import logging

app = Flask(__name__)

# Configure logging to print to stdout
logging.basicConfig(level=logging.INFO)

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
    return redirect('/vuln?id=1')

@app.route('/vuln')
def vuln():
    user_id = request.args.get('id')
    
    if user_id is None:
        return redirect('/vuln?id=1')
    
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        data = cursor.fetchall()
        conn.close()
        
        if len(data) >= 2:
            # 🔥 Log the flag to stdout (so Splunk can capture it)
            flag_msg = f"FLAG-FOUND: You retrieved {len(data)} users! Data: {data}"
            app.logger.info(flag_msg)  # This goes to stdout → Splunk
            return f"🏴 FLAG-FOUND: You retrieved {len(data)} users! Data: {data}"
        else:
            return str(data)
    except Exception as e:
        app.logger.error(f"SQL Error: {e}")
        return f"SQL Error: {e}"

if __name__ == '__main__':
    if not os.path.exists('database.db'):
        init_db()
    app.run(host='0.0.0.0', port=80)