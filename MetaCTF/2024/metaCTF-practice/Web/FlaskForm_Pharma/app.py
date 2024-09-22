#!/usr/bin/env python3

from flask import Flask, render_template, request, jsonify, send_from_directory
import os
app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

# Products Page
@app.route('/products')
def products():
    return render_template('products.html')

@app.route('/products/detail', methods=['POST'])
def product_detail():
    data = request.get_json()  # Get the JSON data
    file_name = './potion_details/' +  data.get('file', 'default_potion')  # Extract the potion file name
    file_content = "File not found."
    try:
        with open(file_name, 'r') as f:
            file_content = f.read()
    except Exception as e:
        file_content = str(e)
    return jsonify({"content": file_content})

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static/images/'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')