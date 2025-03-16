import sys

from env import SECRET_KEY, APP_URI, DB_CONFIG
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
import psycopg2
import jwt
import datetime
import hashlib
import os
import uuid  # For unique token identifiers
import redis  # For token blacklisting

app = Flask(__name__)
CORS(app)

# Redis Configuration (for token blacklisting)
redis_client = redis.Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=6379, db=0)

# JWT Secret Key
SECRET_KEY = SECRET_KEY
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(provided_password, stored_hash):
    return hash_password(provided_password) == stored_hash

# Default route
@app.route('/')
def index():
    return render_template('index.html')


# Login Route
@app.route('/login', methods=['POST'])
def login():
    try:
        # Validate request JSON
        data = request.get_json()
        if not data or "login" not in data or "password" not in data:
            return jsonify({"error": "Missing login or password"}), 400

        login = data['login'].strip().lower()
        password = data['password']

        # Connect to DB and retrieve user
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, password_hash FROM users WHERE LOWER(login) = %s", (login,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user or not verify_password(password, user[1]):
            return jsonify({"error": "Invalid credentials"}), 401

        # Generate JWT token
        user_id = user[0]
        jti = str(uuid.uuid4())  # Unique token identifier
        token = jwt.encode({
            'id': user_id,
            'login': login,
            'exp': datetime.datetime.now() + datetime.timedelta(minutes=5),
            'jti': jti
        }, SECRET_KEY, algorithm='HS256')

        # Store JTI in Redis for blacklisting (5-minute expiry)
        redis_client.setex(jti, 300, "true")

        return jsonify({"token": token})

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500


# Protected Resource Route
@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization').split(' ')[1]  # "Bearer <token>"
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

        # Check if token's JTI is blacklisted
        if redis_client.get(decoded['jti']) is None:
            return jsonify({'error': 'Token already used or expired'}), 401

        # Delete JTI from Redis (one-time use)
        redis_client.delete(decoded['jti'])

        # Redirect to Azure web app with token
        return redirect(APP_URI + f"?token={token}")
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
