#!/usr/bin/env python3
"""
NomadPay Backend API - FIXED Authentication Response Structure
Production-ready Flask API with frontend-compatible authentication responses.
"""

import os
import sqlite3
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Any, Optional

import jwt
import bcrypt
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'nomadpay-secret-key-2024')
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'nomadpay-jwt-secret-2024')
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'nomadpay.db')

# CORS configuration for production
CORS(app, origins=[
    'https://nomadpay-frontend.onrender.com',
    'https://nomadpayadmin.onrender.com',
    'https://tpfviivg.manus.space',
    'https://vkpxlfov.manus.space',
    'http://localhost:3000',
    'http://localhost:3001'
], supports_credentials=True)

class Config:
    SECRET_KEY = app.config['SECRET_KEY']
    JWT_SECRET_KEY = app.config['JWT_SECRET_KEY']
    DATABASE_URL = app.config['DATABASE_URL']
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)

# Rate limiting storage
rate_limit_storage = {}

def rate_limit(max_requests: int, window_minutes: int = 1):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = datetime.utcnow()
            window_start = current_time - timedelta(minutes=window_minutes)
            
            # Clean old entries
            if client_ip in rate_limit_storage:
                rate_limit_storage[client_ip] = [
                    timestamp for timestamp in rate_limit_storage[client_ip]
                    if timestamp > window_start
                ]
            else:
                rate_limit_storage[client_ip] = []
            
            # Check rate limit
            if len(rate_limit_storage[client_ip]) >= max_requests:
                return jsonify({'success': False, 'message': 'Rate limit exceeded'}), 429
            
            # Add current request
            rate_limit_storage[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def get_db():
    """Get database connection"""
    if 'db' not in g:
        g.db = sqlite3.connect(Config.DATABASE_URL)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.teardown_appcontext
def close_db(error):
    close_db()

def init_db():
    """Initialize database with all required tables"""
    try:
        conn = sqlite3.connect(Config.DATABASE_URL)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Wallets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                currency TEXT NOT NULL,
                balance DECIMAL(15,8) DEFAULT 0.00000000,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, currency)
            )
        ''')
        
        # Transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                amount DECIMAL(15,8) NOT NULL,
                currency TEXT NOT NULL,
                recipient_email TEXT,
                description TEXT,
                status TEXT DEFAULT 'completed',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # QR codes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS qr_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code TEXT UNIQUE NOT NULL,
                amount DECIMAL(15,8) NOT NULL,
                currency TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'active',
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Refresh tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                revoked BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
        
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during database initialization: {e}")
        raise

# JWT token functions
def generate_tokens(user_id: int) -> Dict[str, str]:
    """Generate access and refresh tokens"""
    try:
        # Access token payload
        access_payload = {
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + Config.JWT_ACCESS_TOKEN_EXPIRES,
            'iat': datetime.utcnow()
        }
        
        # Refresh token payload
        refresh_payload = {
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + Config.JWT_REFRESH_TOKEN_EXPIRES,
            'iat': datetime.utcnow()
        }
        
        access_token = jwt.encode(access_payload, Config.JWT_SECRET_KEY, algorithm='HS256')
        refresh_token = jwt.encode(refresh_payload, Config.JWT_SECRET_KEY, algorithm='HS256')
        
        # Store refresh token hash in database
        db = get_db()
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        db.execute('''
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
        ''', (user_id, token_hash, datetime.utcnow() + Config.JWT_REFRESH_TOKEN_EXPIRES))
        db.commit()
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
        
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        raise

def verify_token(token: str, token_type: str = 'access') -> Optional[Dict]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
        if payload.get('type') != token_type:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    """Authentication decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_token(token)
        if not payload:
            return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401
        
        g.current_user_id = payload['user_id']
        return f(*args, **kwargs)
    return decorated_function

def log_security_event(event_type: str, severity: str, user_id: Optional[int] = None, details: str = ''):
    """Log security events"""
    try:
        db = get_db()
        db.execute('''
            INSERT INTO security_events (user_id, event_type, severity, details, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, event_type, severity, details, request.remote_addr, request.headers.get('User-Agent', '')))
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'success': True,
        'message': 'NomadPay API is healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200

# ===== FIXED AUTHENTICATION ENDPOINTS =====

@app.route('/api/auth/register', methods=['POST'])
@rate_limit(5)  # 5 registration attempts per minute
def register():
    """User registration with FIXED response structure"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
            
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        # Validation
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters'}), 400
        
        db = get_db()
        
        # Check if user exists
        existing_user = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing_user:
            log_security_event('registration_attempt_existing_email', 'low', details=f'Email: {email}')
            return jsonify({'success': False, 'message': 'Email already registered'}), 409
        
        # Create user
        password_hash = generate_password_hash(password)
        cursor = db.execute('''
            INSERT INTO users (email, password_hash, role, status)
            VALUES (?, ?, ?, ?)
        ''', (email, password_hash, 'user', 'active'))
        
        user_id = cursor.lastrowid
        
        # Create default wallets
        currencies = ['USD', 'EUR', 'BTC', 'ETH']
        for currency in currencies:
            db.execute('''
                INSERT INTO wallets (user_id, currency, balance)
                VALUES (?, ?, ?)
            ''', (user_id, currency, 100.00 if currency in ['USD', 'EUR'] else 0.01))
        
        db.commit()
        
        # Generate tokens
        tokens = generate_tokens(user_id)
        
        log_security_event('user_registered', 'info', user_id, f'New user registered: {email}')
        
        # ✅ FIXED: Return response structure that matches frontend expectations
        response_data = {
            'success': True,
            'message': 'Registration successful',
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token'],
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
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(10)  # 10 login attempts per minute
def login():
    """User login with FIXED response structure"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
            
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'success': False, 'message': 'Email and password are required'}), 400
        
        db = get_db()
        user = db.execute('''
            SELECT id, email, password_hash, role, status, created_at
            FROM users WHERE email = ?
        ''', (email,)).fetchone()
        
        if not user or not check_password_hash(user['password_hash'], password):
            log_security_event('failed_login_attempt', 'medium', details=f'Email: {email}')
            return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
        
        if user['status'] != 'active':
            log_security_event('inactive_user_login_attempt', 'medium', user['id'], f'Inactive user login: {email}')
            return jsonify({'success': False, 'message': 'Account is not active'}), 401
        
        # Generate tokens
        tokens = generate_tokens(user['id'])
        
        log_security_event('user_login', 'info', user['id'], f'User logged in: {email}')
        
        # ✅ FIXED: Return response structure that matches frontend expectations
        response_data = {
            'success': True,
            'message': 'Login successful',
            'access_token': tokens['access_token'],  # ✅ Changed from 'token' to 'access_token'
            'refresh_token': tokens['refresh_token'], # ✅ Added refresh_token
            'user': {
                'id': str(user['id']),
                'email': user['email'],
                'role': user['role'],
                'created_at': user['created_at']
            }
        }
        
        logger.info(f"User logged in successfully: {email}")
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token using refresh token"""
    try:
        data = request.get_json()
        if not data or 'refresh_token' not in data:
            return jsonify({'success': False, 'message': 'Refresh token required'}), 400
        
        refresh_token = data['refresh_token']
        payload = verify_token(refresh_token, 'refresh')
        
        if not payload:
            return jsonify({'success': False, 'message': 'Invalid or expired refresh token'}), 401
        
        # Check if refresh token exists and is not revoked
        db = get_db()
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        stored_token = db.execute('''
            SELECT id, user_id, expires_at, revoked FROM refresh_tokens 
            WHERE token_hash = ?
        ''', (token_hash,)).fetchone()
        
        if not stored_token or stored_token['revoked']:
            return jsonify({'success': False, 'message': 'Refresh token revoked'}), 401
        
        # Generate new tokens
        tokens = generate_tokens(payload['user_id'])
        
        # Revoke old refresh token
        db.execute('UPDATE refresh_tokens SET revoked = TRUE WHERE id = ?', (stored_token['id'],))
        db.commit()
        
        # ✅ FIXED: Return consistent response structure
        response_data = {
            'success': True,
            'message': 'Token refreshed successfully',
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'success': False, 'message': 'Token refresh failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """User logout - revoke refresh tokens"""
    try:
        # Revoke all refresh tokens for the user
        db = get_db()
        db.execute('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ?', (g.current_user_id,))
        db.commit()
        
        log_security_event('user_logout', 'info', g.current_user_id, 'User logged out')
        
        return jsonify({
            'success': True,
            'message': 'Logged out successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'success': False, 'message': 'Logout failed'}), 500

# ===== WALLET ENDPOINTS =====

@app.route('/api/wallet/balances', methods=['GET'])
@require_auth
def get_wallet_balances():
    """Get user wallet balances"""
    try:
        db = get_db()
        wallets = db.execute('''
            SELECT currency, balance FROM wallets WHERE user_id = ?
        ''', (g.current_user_id,)).fetchall()
        
        balances = {wallet['currency']: float(wallet['balance']) for wallet in wallets}
        
        return jsonify({
            'success': True,
            'balances': balances
        }), 200
        
    except Exception as e:
        logger.error(f"Get balances error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get balances'}), 500

# ===== TRANSACTION ENDPOINTS =====

@app.route('/api/transactions', methods=['GET'])
@require_auth
def get_transactions():
    """Get user transaction history"""
    try:
        db = get_db()
        transactions = db.execute('''
            SELECT id, type, amount, currency, recipient_email, description, status, created_at
            FROM transactions WHERE user_id = ?
            ORDER BY created_at DESC LIMIT 50
        ''', (g.current_user_id,)).fetchall()
        
        transaction_list = []
        for tx in transactions:
            transaction_list.append({
                'id': tx['id'],
                'type': tx['type'],
                'amount': float(tx['amount']),
                'currency': tx['currency'],
                'recipient_email': tx['recipient_email'],
                'description': tx['description'],
                'status': tx['status'],
                'created_at': tx['created_at']
            })
        
        return jsonify({
            'success': True,
            'transactions': transaction_list
        }), 200
        
    except Exception as e:
        logger.error(f"Get transactions error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get transactions'}), 500

@app.route('/api/transactions/send', methods=['POST'])
@require_auth
@rate_limit(20)  # 20 transactions per minute
def send_money():
    """Send money to another user"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        recipient_email = data.get('recipient_email', '').lower().strip()
        amount = float(data.get('amount', 0))
        currency = data.get('currency', 'USD').upper()
        description = data.get('description', '')
        
        if not recipient_email or amount <= 0:
            return jsonify({'success': False, 'message': 'Valid recipient email and amount required'}), 400
        
        db = get_db()
        
        # Check recipient exists
        recipient = db.execute('SELECT id FROM users WHERE email = ?', (recipient_email,)).fetchone()
        if not recipient:
            return jsonify({'success': False, 'message': 'Recipient not found'}), 404
        
        # Check sender balance
        sender_wallet = db.execute('''
            SELECT balance FROM wallets WHERE user_id = ? AND currency = ?
        ''', (g.current_user_id, currency)).fetchone()
        
        if not sender_wallet or sender_wallet['balance'] < amount:
            return jsonify({'success': False, 'message': 'Insufficient balance'}), 400
        
        # Process transaction
        # Deduct from sender
        db.execute('''
            UPDATE wallets SET balance = balance - ? WHERE user_id = ? AND currency = ?
        ''', (amount, g.current_user_id, currency))
        
        # Add to recipient
        db.execute('''
            UPDATE wallets SET balance = balance + ? WHERE user_id = ? AND currency = ?
        ''', (amount, recipient['id'], currency))
        
        # Record transaction
        db.execute('''
            INSERT INTO transactions (user_id, type, amount, currency, recipient_email, description)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (g.current_user_id, 'send', amount, currency, recipient_email, description))
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': 'Money sent successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Send money error: {e}")
        return jsonify({'success': False, 'message': 'Transaction failed'}), 500

# ===== QR CODE ENDPOINTS =====

@app.route('/api/qr/generate', methods=['POST'])
@require_auth
def generate_qr():
    """Generate QR code for payment"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data provided'}), 400
        
        amount = float(data.get('amount', 0))
        currency = data.get('currency', 'USD').upper()
        description = data.get('description', '')
        
        if amount <= 0:
            return jsonify({'success': False, 'message': 'Valid amount required'}), 400
        
        # Generate unique QR code
        qr_code = secrets.token_urlsafe(16)
        expires_at = datetime.utcnow() + timedelta(hours=24)  # QR expires in 24 hours
        
        db = get_db()
        db.execute('''
            INSERT INTO qr_codes (user_id, code, amount, currency, description, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (g.current_user_id, qr_code, amount, currency, description, expires_at))
        db.commit()
        
        return jsonify({
            'success': True,
            'qr_code': qr_code,
            'amount': amount,
            'currency': currency,
            'description': description,
            'expires_at': expires_at.isoformat()
        }), 201
        
    except Exception as e:
        logger.error(f"QR generation error: {e}")
        return jsonify({'success': False, 'message': 'QR generation failed'}), 500

# ===== ADMIN ENDPOINTS =====

@app.route('/api/admin/users', methods=['GET'])
@require_auth
def get_users():
    """Get all users (admin only)"""
    try:
        # Check if user is admin
        db = get_db()
        user = db.execute('SELECT role FROM users WHERE id = ?', (g.current_user_id,)).fetchone()
        if not user or user['role'] != 'admin':
            return jsonify({'success': False, 'message': 'Admin access required'}), 403
        
        users = db.execute('''
            SELECT id, email, role, status, created_at FROM users
            ORDER BY created_at DESC
        ''').fetchall()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user['id'],
                'email': user['email'],
                'role': user['role'],
                'status': user['status'],
                'created_at': user['created_at']
            })
        
        return jsonify({
            'success': True,
            'users': user_list
        }), 200
        
    except Exception as e:
        logger.error(f"Get users error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get users'}), 500

# Initialize database on startup
@app.before_first_request
def initialize_database():
    """Initialize database before first request"""
    init_db()

# Cleanup database connections
@app.teardown_appcontext
def close_db(error):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

