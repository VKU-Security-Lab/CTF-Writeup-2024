from flask import Flask, request, render_template, redirect, url_for, session
import mysql.connector
import time
import secrets
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = secrets.token_bytes(64)

def get_db_connection(retries=5, delay=5):
    for _ in range(retries):
        try:
            return mysql.connector.connect(
                host="127.0.0.1",
                user="user",
                password="password",
                database="challenge",
                charset="utf8mb4",
                collation="utf8mb4_general_ci"
            )
        except mysql.connector.Error as err:
            print(f"Error: {err}")
            time.sleep(delay)
    raise Exception("Could not connect to the database after several attempts")

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        salt=secrets.token_hex(16)
        password = hashlib.sha256(bytes.fromhex(salt) + password.encode()).hexdigest()

        query = "INSERT INTO users (username, password, salt) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, password, salt))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = "SELECT password, salt FROM users WHERE username=%s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()
        
        # Ensure all results are read
        cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        if user:
            stored_password, salt = user
            # Hash the provided password with the stored salt
            hashed_password = hashlib.sha256(bytes.fromhex(salt) + password.encode()).hexdigest()
            
            if hashed_password == stored_password:
                session['username'] = username  # Store username in session
                return redirect(url_for('home'))  # Redirect to home page
            else:
                return "Login failed"
        else:
            return "Login failed"
    
    return render_template('login.html')

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = f"SELECT username, created_at FROM users WHERE username='{username}'"
    cursor.execute(query)
    user = cursor.fetchone()

    # Ensure all results are read
    cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    if user:
        username, created_at = user
        try:
            membership_duration = (datetime.now() - created_at).seconds
            return render_template('profile.html', username=username, membership_duration=membership_duration)
        except Exception as e:
            return f"Error: Database result could not be converted into a timestamp. Details: {e}"
    else:
        return "User not found"

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
