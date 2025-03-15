from env import SECRET_KEY, APP_URI
from flask import Flask, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
from passlib.hash import bcrypt
import os
import uuid  # For unique token identifiers
import redis  # For token blacklisting

app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
db = SQLAlchemy(app)

# Redis Configuration (for token blacklisting)
redis_client = redis.Redis(host=os.getenv('REDIS_HOST', 'localhost'), port=6379, db=0)


# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


# JWT Secret Key
SECRET_KEY = SECRET_KEY


# Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(login=data['login']).first()

    if user and bcrypt.verify(data['password'], user.password_hash):
        jti = str(uuid.uuid4())  # Unique token identifier
        token = jwt.encode({
            'id': user.id,
            'login': user.login,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
            'jti': jti
        }, SECRET_KEY, algorithm='HS256')

        # Store JTI in Redis with expiry
        redis_client.set(jti, 'true', ex=300)  # 5-minute expiry

        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401


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
    app.run(debug=True)
