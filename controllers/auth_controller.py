"""
NomadPay Backend API - Authentication Controller
Fixed version with correct response structure for frontend compatibility
"""

from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import sqlite3
from datetime import datetime, timedelta
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthController:
    def __init__(self, db_path='nomadpay.db', secret_key='your-secret-key-here'):
        self.db_path = db_path
        self.secret_key = secret_key
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create wallets table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS wallets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    currency TEXT NOT NULL,
                    balance DECIMAL(15,2) DEFAULT 0.00,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise
    
    def generate_tokens(self, user_id, email, role='user'):
        """Generate access and refresh tokens"""
        try:
            # Access token (1 hour expiry)
            access_payload = {
                'user_id': user_id,
                'email': email,
                'role': role,
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow(),
                'type': 'access'
            }
            
            # Refresh token (7 days expiry)
            refresh_payload = {
                'user_id': user_id,
                'email': email,
                'exp': datetime.utcnow() + timedelta(days=7),
                'iat': datetime.utcnow(),
                'type': 'refresh'
            }
            
            access_token = jwt.encode(access_payload, self.secret_key, algorithm='HS256')
            refresh_token = jwt.encode(refresh_payload, self.secret_key, algorithm='HS256')
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }
            
        except Exception as e:
            logger.error(f"Token generation error: {e}")
            raise
    
    def create_default_wallets(self, user_id):
        """Create default wallets for new user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create default wallets for major currencies
            currencies = ['USD', 'EUR', 'BTC', 'ETH']
            for currency in currencies:
                cursor.execute('''
                    INSERT INTO wallets (user_id, currency, balance)
                    VALUES (?, ?, 0.00)
                ''', (user_id, currency))
            
            conn.commit()
            conn.close()
            logger.info(f"Default wallets created for user {user_id}")
            
        except Exception as e:
            logger.error(f"Wallet creation error: {e}")
            raise
    
    def register(self):
        """Handle user registration with FIXED response structure"""
        try:
            data = request.get_json()
            
            # Validate input
            if not data or not data.get('email') or not data.get('password'):
                return jsonify({
                    'success': False,
                    'message': 'Email and password are required'
                }), 400
            
            email = data['email'].lower().strip()
            password = data['password']
            
            # Validate email format
            if '@' not in email or '.' not in email:
                return jsonify({
                    'success': False,
                    'message': 'Invalid email format'
                }), 400
            
            # Validate password strength
            if len(password) < 8:
                return jsonify({
                    'success': False,
                    'message': 'Password must be at least 8 characters long'
                }), 400
            
            # Check if user already exists
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cursor.fetchone():
                conn.close()
                return jsonify({
                    'success': False,
                    'message': 'User already exists with this email'
                }), 409
            
            # Create new user
            password_hash = generate_password_hash(password)
            cursor.execute('''
                INSERT INTO users (email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?)
            ''', (email, password_hash, 'user', datetime.utcnow().isoformat()))
            
            user_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            # Create default wallets
            self.create_default_wallets(user_id)
            
            # Generate tokens
            tokens = self.generate_tokens(user_id, email, 'user')
            
            # ✅ FIXED: Return correct response structure with access_token and refresh_token
            response_data = {
                'success': True,
                'message': 'Registration successful',
                'access_token': tokens['access_token'],    # ✅ FIXED: Changed from "token"
                'refresh_token': tokens['refresh_token'],  # ✅ FIXED: Added refresh_token
                'user': {
                    'id': str(user_id),
                    'email': email,
                    'role': 'user',
                    'created_at': datetime.utcnow().isoformat()
                }
            }
            
            logger.info(f"User registered successfully: {email}")
            return jsonify(response_data), 201
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return jsonify({
                'success': False,
                'message': 'Registration failed. Please try again.'
            }), 500
    
    def login(self):
        """Handle user login with FIXED response structure"""
        try:
            data = request.get_json()
            
            # Validate input
            if not data or not data.get('email') or not data.get('password'):
                return jsonify({
                    'success': False,
                    'message': 'Email and password are required'
                }), 400
            
            email = data['email'].lower().strip()
            password = data['password']
            
            # Find user in database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, email, password_hash, role, created_at
                FROM users WHERE email = ?
            ''', (email,))
            
            user = cursor.fetchone()
            conn.close()
            
            if not user:
                return jsonify({
                    'success': False,
                    'message': 'Invalid email or password'
                }), 401
            
            user_id, user_email, password_hash, role, created_at = user
            
            # Verify password
            if not check_password_hash(password_hash, password):
                return jsonify({
                    'success': False,
                    'message': 'Invalid email or password'
                }), 401
            
            # Generate tokens
            tokens = self.generate_tokens(user_id, user_email, role)
            
            # ✅ FIXED: Return correct response structure with access_token and refresh_token
            response_data = {
                'success': True,
                'message': 'Login successful',
                'access_token': tokens['access_token'],    # ✅ FIXED: Changed from "token"
                'refresh_token': tokens['refresh_token'],  # ✅ FIXED: Added refresh_token
                'user': {
                    'id': str(user_id),
                    'email': user_email,
                    'role': role,
                    'created_at': created_at
                }
            }
            
            logger.info(f"User logged in successfully: {email}")
            return jsonify(response_data), 200
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({
                'success': False,
                'message': 'Login failed. Please try again.'
            }), 500
    
    def refresh_token(self):
        """Handle token refresh"""
        try:
            data = request.get_json()
            
            if not data or not data.get('refresh_token'):
                return jsonify({
                    'success': False,
                    'message': 'Refresh token is required'
                }), 400
            
            refresh_token = data['refresh_token']
            
            # Verify refresh token
            try:
                payload = jwt.decode(refresh_token, self.secret_key, algorithms=['HS256'])
                
                if payload.get('type') != 'refresh':
                    raise jwt.InvalidTokenError('Invalid token type')
                
                user_id = payload['user_id']
                email = payload['email']
                role = payload.get('role', 'user')
                
                # Generate new tokens
                tokens = self.generate_tokens(user_id, email, role)
                
                response_data = {
                    'success': True,
                    'message': 'Token refreshed successfully',
                    'access_token': tokens['access_token'],    # ✅ FIXED: Consistent field names
                    'refresh_token': tokens['refresh_token']   # ✅ FIXED: Consistent field names
                }
                
                return jsonify(response_data), 200
                
            except jwt.ExpiredSignatureError:
                return jsonify({
                    'success': False,
                    'message': 'Refresh token has expired'
                }), 401
            except jwt.InvalidTokenError:
                return jsonify({
                    'success': False,
                    'message': 'Invalid refresh token'
                }), 401
                
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return jsonify({
                'success': False,
                'message': 'Token refresh failed'
            }), 500
    
    def logout(self):
        """Handle user logout"""
        try:
            # In a production environment, you would invalidate the tokens
            # For now, we'll just return a success response
            response_data = {
                'success': True,
                'message': 'Logout successful'
            }
            
            return jsonify(response_data), 200
            
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return jsonify({
                'success': False,
                'message': 'Logout failed'
            }), 500

