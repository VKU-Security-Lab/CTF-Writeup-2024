from flask import Flask, request, render_template
import random
import os
import sqlite3
import hashlib

os.chdir(os.path.dirname(os.path.realpath(__file__)))

db = sqlite3.connect("db.sqlite", check_same_thread=False)
db_cursor = db.cursor()

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
@app.route('/index.html', methods=['GET', 'POST'])
def index():
    return render_template("index.html")

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username", "-")
    password_hash = hashlib.md5(data.get("password", "-").encode()).hexdigest()

    db_error = ""
    try:
        query = "SELECT username, public_btc_address, private_btc_key, balance FROM users WHERE username='" + username + "' AND password_hash='" + password_hash + "';"
        result = db_cursor.execute(query)
        user_data = result.fetchone()
    except Exception as e:
        user_data = None
        db_error = str(e)

    if user_data is None:
        return {
            "error": True,
            "message": "Login failed. Please try again.",
            "debug": query,
            "debug_msg": db_error,
        }
    else:
        return {
            "error": False,
            "message": "Login successful.",
            "username": user_data[0],
            "public_btc_address": user_data[1],
            "private_btc_key": user_data[2],
            "balance": user_data[3]
        }

app.run(debug=True, host="0.0.0.0")
