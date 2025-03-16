from env import SECRET_KEY, APP_URI
from flask import Flask, request, jsonify, redirect, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
import hashlib
import sqlalchemy
import os
import uuid  # For unique token identifiers
import redis  # For token blacklisting

app = Flask(__name__)
CORS(app)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = \
    'postgresql://myadmin:MyStrongPassword123@auth-postgres-server.postgres.database.azure.com:5432/credentials'
db = SQLAlchemy(app)

# Redis Configuration (for token blacklisting)
redis_client = redis.Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=6379, db=0)


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


# JWT Secret Key
SECRET_KEY = SECRET_KEY

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

    with db.engine.connect() as connection:
        result = connection.execute(sqlalchemy.text("SELECT login FROM users"))
        users = []
        for row in result:
            users.append(f"👤 User in DB: {row[0]}")

    data = request.json
    if not data or 'login' not in data or 'password' not in data:
        return jsonify({'error': 'Missing login or password'}), 400

    login = data['login'].strip().lower()
    password = data['password']

    user = User.query.filter(sqlalchemy.func.lower(User.login) == login).first()
    print("🗂️ Retrieved User:", user.__dict__ if user else "User not found")
    if not user or not verify_password(password, user.password_hash):
        return jsonify({'error': 'Invalid credentials'}), 401

    if user and hashlib.sha256(data['password'].encode()).hexdigest() == user.password_hash:
        jti = str(uuid.uuid4())  # Unique token identifier
        token = jwt.encode({
            'id': user.id,
            'login': user.login,
            'exp': datetime.datetime.now() + datetime.timedelta(minutes=5),
            'jti': jti
        }, SECRET_KEY, algorithm='HS256')

        # Store JTI in Redis with expiry
        redis_client.set(jti, 'true', ex=300)  # 5-minute expiry

        return jsonify({'token': token})
    return jsonify({'error': f'Invalid credentials {data}'}), 401


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
    with app.app_context():
        db.create_all()  # Ensures tables are created
    app.run(host='0.0.0.0', port=5000, debug=True)
