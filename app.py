#!/usr/bin/env python3
"""
NomadPay Backend API - Production Ready Flask Application
Complete financial platform backend with security, authentication, and admin features

Note: Uses Python's built-in sqlite3 module (no external dependency required)
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import sqlite3  # Built-in Python module - no pip install required
import os
import logging
from datetime import datetime, timedelta
from functools import wraps
import secrets
import hashlib
import time
from typing import Dict, List, Optional, Any

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', secrets.token_hex(32))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=7)
    DATABASE_URL = os.environ.get('DATABASE_URL', 'nomadpay.db')
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    RATE_LIMIT_PER_MINUTE = int(os.environ.get('RATE_LIMIT_PER_MINUTE', '60'))
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Configure CORS
CORS(app, origins=Config.CORS_ORIGINS, supports_credentials=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO if not Config.DEBUG else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database initialization
def init_db():
    """Initialize the database with all required tables"""
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
                balance DECIMAL(15,2) DEFAULT 0.00,
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
                amount DECIMAL(15,2) NOT NULL,
                currency TEXT NOT NULL,
                recipient TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # QR codes table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS qr_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                wallet_address TEXT NOT NULL,
                amount DECIMAL(15,2) DEFAULT 0.00,
                currency TEXT DEFAULT 'USD',
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Security logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                severity TEXT DEFAULT 'info',
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Audit logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_user TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                details TEXT,
                ip_address TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Refresh tokens table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                revoked BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Rate limiting table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                requests INTEGER DEFAULT 1,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip_address, endpoint)
            )
        ''')
        
        # Create default admin user if not exists
        cursor.execute('SELECT id FROM users WHERE email = ?', ('admin@nomadpay.io',))
        if not cursor.fetchone():
            admin_password = generate_password_hash('admin123')
            cursor.execute('''
                INSERT INTO users (email, password_hash, role, status)
                VALUES (?, ?, ?, ?)
            ''', ('admin@nomadpay.io', admin_password, 'admin', 'active'))
            
            # Create default wallets for admin
            admin_id = cursor.lastrowid
            currencies = ['USD', 'EUR', 'BTC', 'ETH']
            for currency in currencies:
                cursor.execute('''
                    INSERT INTO wallets (user_id, currency, balance)
                    VALUES (?, ?, ?)
                ''', (admin_id, currency, 1000.00 if currency in ['USD', 'EUR'] else 0.1))
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
        
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during database initialization: {e}")
        raise

# Database helper functions
def get_db():
    """Get database connection"""
    if 'db' not in g:
        try:
            g.db = sqlite3.connect(Config.DATABASE_URL)
            g.db.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            raise
    return g.db

def close_db(error):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        try:
            db.close()
        except sqlite3.Error as e:
            logger.error(f"Database close error: {e}")

@app.teardown_appcontext
def close_db_handler(error):
    close_db(error)

# Security utilities
def log_security_event(event_type: str, severity: str = 'info', user_id: Optional[int] = None, details: str = ''):
    """Log security events"""
    try:
        db = get_db()
        db.execute('''
            INSERT INTO security_logs (user_id, event_type, ip_address, user_agent, severity, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, event_type, request.remote_addr, request.headers.get('User-Agent', ''), severity, details))
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log security event: {e}")

def log_audit_event(admin_user: str, action: str, resource_type: str = '', resource_id: str = '', details: str = ''):
    """Log audit events"""
    try:
        db = get_db()
        db.execute('''
            INSERT INTO audit_logs (admin_user, action, resource_type, resource_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (admin_user, action, resource_type, resource_id, details, request.remote_addr))
        db.commit()
    except Exception as e:
        logger.error(f"Failed to log audit event: {e}")

def check_rate_limit(endpoint: str, limit: int = None) -> bool:
    """Check rate limiting"""
    if limit is None:
        limit = Config.RATE_LIMIT_PER_MINUTE
    
    ip_address = request.remote_addr
    current_time = datetime.utcnow()
    window_start = current_time - timedelta(minutes=1)
    
    try:
        db = get_db()
        
        # Clean old entries
        db.execute('DELETE FROM rate_limits WHERE window_start < ?', (window_start,))
        
        # Check current requests
        cursor = db.execute('''
            SELECT requests FROM rate_limits 
            WHERE ip_address = ? AND endpoint = ? AND window_start >= ?
        ''', (ip_address, endpoint, window_start))
        
        result = cursor.fetchone()
        
        if result:
            if result['requests'] >= limit:
                return False
            # Update request count
            db.execute('''
                UPDATE rate_limits SET requests = requests + 1 
                WHERE ip_address = ? AND endpoint = ?
            ''', (ip_address, endpoint))
        else:
            # Create new entry
            db.execute('''
                INSERT OR REPLACE INTO rate_limits (ip_address, endpoint, requests, window_start)
                VALUES (?, ?, 1, ?)
            ''', (ip_address, endpoint, current_time))
        
        db.commit()
        return True
        
    except Exception as e:
        logger.error(f"Rate limit check failed: {e}")
        return True  # Allow request on error

# JWT utilities
def generate_tokens(user_id: int) -> Dict[str, str]:
    """Generate access and refresh tokens"""
    now = datetime.utcnow()
    
    # Access token
    access_payload = {
        'user_id': user_id,
        'exp': now + Config.JWT_ACCESS_TOKEN_EXPIRES,
        'iat': now,
        'type': 'access'
    }
    access_token = jwt.encode(access_payload, Config.JWT_SECRET_KEY, algorithm='HS256')
    
    # Refresh token
    refresh_payload = {
        'user_id': user_id,
        'exp': now + Config.JWT_REFRESH_TOKEN_EXPIRES,
        'iat': now,
        'type': 'refresh'
    }
    refresh_token = jwt.encode(refresh_payload, Config.JWT_SECRET_KEY, algorithm='HS256')
    
    # Store refresh token hash
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    try:
        db = get_db()
        db.execute('''
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
        ''', (user_id, token_hash, now + Config.JWT_REFRESH_TOKEN_EXPIRES))
        db.commit()
    except Exception as e:
        logger.error(f"Failed to store refresh token: {e}")
    
    return {
        'access_token': access_token,
        'refresh_token': refresh_token
    }

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

# Authentication decorators
def token_required(f):
    """Decorator to require valid JWT token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                pass
        
        if not token:
            log_security_event('unauthorized_access', 'warning', details='Missing token')
            return jsonify({'success': False, 'message': 'Token is missing'}), 401
        
        payload = verify_token(token)
        if not payload:
            log_security_event('invalid_token', 'warning', details='Invalid or expired token')
            return jsonify({'success': False, 'message': 'Token is invalid or expired'}), 401
        
        g.current_user_id = payload['user_id']
        return f(*args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            db = get_db()
            user = db.execute('SELECT role FROM users WHERE id = ?', (g.current_user_id,)).fetchone()
            
            if not user or user['role'] != 'admin':
                log_security_event('unauthorized_admin_access', 'high', g.current_user_id, 'Non-admin attempted admin access')
                return jsonify({'success': False, 'message': 'Admin access required'}), 403
            
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Admin check error: {e}")
            return jsonify({'success': False, 'message': 'Authorization check failed'}), 500
    
    return decorated

def rate_limit(limit: int = None):
    """Decorator for rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            endpoint = request.endpoint or f.__name__
            if not check_rate_limit(endpoint, limit):
                log_security_event('rate_limit_exceeded', 'medium', details=f'Endpoint: {endpoint}')
                return jsonify({'success': False, 'message': 'Rate limit exceeded'}), 429
            return f(*args, **kwargs)
        return decorated
    return decorator

# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db = get_db()
        db.execute('SELECT 1').fetchone()
        
        return jsonify({
            'success': True,
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0',
            'database': 'connected'
        })
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'success': False,
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'version': '2.0.0',
            'error': 'Database connection failed'
        }), 500

# Authentication endpoints
@app.route('/api/auth/register', methods=['POST'])
@rate_limit(5)  # 5 registrations per minute
def register():
    """User registration"""
    try:
        data = request.get_json()
        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        
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
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'user': {
                'id': str(user_id),
                'email': email,
                'created_at': datetime.utcnow().isoformat()
            },
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        }), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(10)  # 10 login attempts per minute
def login():
    """User login"""
    try:
        data = request.get_json()
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
            log_security_event('login_failed', 'medium', details=f'Email: {email}')
            return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
        
        if user['status'] != 'active':
            log_security_event('login_inactive_account', 'medium', user['id'], f'Inactive account login: {email}')
            return jsonify({'success': False, 'message': 'Account is not active'}), 403
        
        # Generate tokens
        tokens = generate_tokens(user['id'])
        
        log_security_event('user_login', 'info', user['id'], f'User logged in: {email}')
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': str(user['id']),
                'email': user['email'],
                'role': user['role'],
                'created_at': user['created_at']
            },
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        })
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed'}), 500

@app.route('/api/auth/refresh', methods=['POST'])
@rate_limit(20)  # 20 refresh attempts per minute
def refresh_token():
    """Refresh access token"""
    try:
        data = request.get_json()
        refresh_token = data.get('refresh_token', '')
        
        if not refresh_token:
            return jsonify({'success': False, 'message': 'Refresh token is required'}), 400
        
        # Verify refresh token
        payload = verify_token(refresh_token, 'refresh')
        if not payload:
            log_security_event('invalid_refresh_token', 'medium', details='Invalid refresh token')
            return jsonify({'success': False, 'message': 'Invalid refresh token'}), 401
        
        # Check if token exists and is not revoked
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        db = get_db()
        stored_token = db.execute('''
            SELECT id, user_id, expires_at, revoked
            FROM refresh_tokens
            WHERE token_hash = ? AND user_id = ?
        ''', (token_hash, payload['user_id'])).fetchone()
        
        if not stored_token or stored_token['revoked']:
            log_security_event('revoked_refresh_token', 'high', payload['user_id'], 'Revoked refresh token used')
            return jsonify({'success': False, 'message': 'Refresh token is revoked'}), 401
        
        # Generate new tokens
        tokens = generate_tokens(payload['user_id'])
        
        # Revoke old refresh token
        db.execute('UPDATE refresh_tokens SET revoked = TRUE WHERE id = ?', (stored_token['id'],))
        db.commit()
        
        log_security_event('token_refreshed', 'info', payload['user_id'], 'Access token refreshed')
        
        return jsonify({
            'success': True,
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        })
        
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return jsonify({'success': False, 'message': 'Token refresh failed'}), 500

@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    """User logout"""
    try:
        # Revoke all refresh tokens for user
        db = get_db()
        db.execute('UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = ?', (g.current_user_id,))
        db.commit()
        
        log_security_event('user_logout', 'info', g.current_user_id, 'User logged out')
        
        return jsonify({
            'success': True,
            'message': 'Logout successful'
        })
        
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return jsonify({'success': False, 'message': 'Logout failed'}), 500

# Wallet endpoints
@app.route('/api/wallet/balances', methods=['GET'])
@token_required
@rate_limit()
def get_wallet_balances():
    """Get user wallet balances"""
    try:
        db = get_db()
        wallets = db.execute('''
            SELECT currency, balance, updated_at
            FROM wallets
            WHERE user_id = ?
            ORDER BY currency
        ''', (g.current_user_id,)).fetchall()
        
        wallet_list = []
        for wallet in wallets:
            wallet_list.append({
                'currency': wallet['currency'],
                'balance': str(wallet['balance']),
                'updated_at': wallet['updated_at']
            })
        
        return jsonify({
            'success': True,
            'wallets': wallet_list
        })
        
    except Exception as e:
        logger.error(f"Get wallet balances error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get wallet balances'}), 500

# Transaction endpoints
@app.route('/api/transactions', methods=['GET'])
@token_required
@rate_limit()
def get_transactions():
    """Get user transactions"""
    try:
        db = get_db()
        transactions = db.execute('''
            SELECT id, type, amount, currency, recipient, status, created_at
            FROM transactions
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT 50
        ''', (g.current_user_id,)).fetchall()
        
        transaction_list = []
        for tx in transactions:
            transaction_list.append({
                'id': str(tx['id']),
                'type': tx['type'],
                'amount': float(tx['amount']),
                'currency': tx['currency'],
                'recipient': tx['recipient'],
                'status': tx['status'],
                'created_at': tx['created_at']
            })
        
        return jsonify({
            'success': True,
            'transactions': transaction_list
        })
        
    except Exception as e:
        logger.error(f"Get transactions error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get transactions'}), 500

@app.route('/api/transactions/send', methods=['POST'])
@token_required
@rate_limit(10)  # 10 transactions per minute
def send_money():
    """Send money transaction"""
    try:
        data = request.get_json()
        recipient = data.get('recipient', '').strip()
        amount = float(data.get('amount', 0))
        currency = data.get('currency', 'USD').upper()
        
        if not recipient or amount <= 0:
            return jsonify({'success': False, 'message': 'Invalid recipient or amount'}), 400
        
        if currency not in ['USD', 'EUR', 'BTC', 'ETH']:
            return jsonify({'success': False, 'message': 'Unsupported currency'}), 400
        
        db = get_db()
        
        # Check wallet balance
        wallet = db.execute('''
            SELECT balance FROM wallets
            WHERE user_id = ? AND currency = ?
        ''', (g.current_user_id, currency)).fetchone()
        
        if not wallet or float(wallet['balance']) < amount:
            return jsonify({'success': False, 'message': 'Insufficient balance'}), 400
        
        # Create transaction
        cursor = db.execute('''
            INSERT INTO transactions (user_id, type, amount, currency, recipient, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (g.current_user_id, 'send', amount, currency, recipient, 'completed'))
        
        transaction_id = cursor.lastrowid
        
        # Update wallet balance
        new_balance = float(wallet['balance']) - amount
        db.execute('''
            UPDATE wallets SET balance = ?, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND currency = ?
        ''', (new_balance, g.current_user_id, currency))
        
        db.commit()
        
        log_security_event('transaction_sent', 'info', g.current_user_id, 
                         f'Sent {amount} {currency} to {recipient}')
        
        return jsonify({
            'success': True,
            'message': 'Transaction completed successfully',
            'transaction_id': str(transaction_id),
            'new_balance': str(new_balance)
        })
        
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount format'}), 400
    except Exception as e:
        logger.error(f"Send money error: {e}")
        return jsonify({'success': False, 'message': 'Transaction failed'}), 500

# QR Code endpoints
@app.route('/api/qr/generate', methods=['POST'])
@token_required
@rate_limit(30)  # 30 QR generations per minute
def generate_qr():
    """Generate QR code for payments"""
    try:
        data = request.get_json()
        amount = float(data.get('amount', 0))
        currency = data.get('currency', 'USD').upper()
        
        if currency not in ['USD', 'EUR', 'BTC', 'ETH']:
            return jsonify({'success': False, 'message': 'Unsupported currency'}), 400
        
        # Generate wallet address
        wallet_address = f"nomadpay_{g.current_user_id}_{int(time.time())}"
        
        db = get_db()
        cursor = db.execute('''
            INSERT INTO qr_codes (user_id, wallet_address, amount, currency, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (g.current_user_id, wallet_address, amount, currency, 'active'))
        
        qr_id = cursor.lastrowid
        db.commit()
        
        log_security_event('qr_generated', 'info', g.current_user_id, 
                         f'QR code generated for {amount} {currency}')
        
        return jsonify({
            'success': True,
            'qr_id': str(qr_id),
            'wallet_address': wallet_address,
            'amount': amount,
            'currency': currency,
            'qr_code': f"data:qr_code_placeholder_{qr_id}"
        })
        
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid amount format'}), 400
    except Exception as e:
        logger.error(f"QR generation error: {e}")
        return jsonify({'success': False, 'message': 'QR generation failed'}), 500

# Admin endpoints
@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
@rate_limit()
def admin_get_users():
    """Get all users (admin only)"""
    try:
        db = get_db()
        users = db.execute('''
            SELECT id, email, role, status, created_at, updated_at
            FROM users
            ORDER BY created_at DESC
        ''').fetchall()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': str(user['id']),
                'email': user['email'],
                'role': user['role'],
                'status': user['status'],
                'created_at': user['created_at'],
                'updated_at': user['updated_at']
            })
        
        log_audit_event('admin@nomadpay.io', 'view_users', 'users', '', 'Viewed user list')
        
        return jsonify({
            'success': True,
            'users': user_list
        })
        
    except Exception as e:
        logger.error(f"Admin get users error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get users'}), 500

@app.route('/api/admin/transactions', methods=['GET'])
@token_required
@admin_required
@rate_limit()
def admin_get_transactions():
    """Get all transactions (admin only)"""
    try:
        db = get_db()
        transactions = db.execute('''
            SELECT t.id, t.user_id, t.type, t.amount, t.currency, 
                   t.recipient, t.status, t.created_at, u.email
            FROM transactions t
            JOIN users u ON t.user_id = u.id
            ORDER BY t.created_at DESC
            LIMIT 100
        ''').fetchall()
        
        transaction_list = []
        for tx in transactions:
            transaction_list.append({
                'id': str(tx['id']),
                'user_id': str(tx['user_id']),
                'user_email': tx['email'],
                'type': tx['type'],
                'amount': float(tx['amount']),
                'currency': tx['currency'],
                'recipient': tx['recipient'],
                'status': tx['status'],
                'created_at': tx['created_at']
            })
        
        log_audit_event('admin@nomadpay.io', 'view_transactions', 'transactions', '', 'Viewed transaction list')
        
        return jsonify({
            'success': True,
            'transactions': transaction_list
        })
        
    except Exception as e:
        logger.error(f"Admin get transactions error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get transactions'}), 500

@app.route('/api/admin/wallets', methods=['GET'])
@token_required
@admin_required
@rate_limit()
def admin_get_wallets():
    """Get all wallet balances (admin only)"""
    try:
        db = get_db()
        wallets = db.execute('''
            SELECT w.user_id, w.currency, w.balance, w.updated_at, u.email
            FROM wallets w
            JOIN users u ON w.user_id = u.id
            ORDER BY w.updated_at DESC
        ''').fetchall()
        
        wallet_list = []
        for wallet in wallets:
            wallet_list.append({
                'user_id': str(wallet['user_id']),
                'user_email': wallet['email'],
                'currency': wallet['currency'],
                'balance': str(wallet['balance']),
                'updated_at': wallet['updated_at']
            })
        
        log_audit_event('admin@nomadpay.io', 'view_wallets', 'wallets', '', 'Viewed wallet balances')
        
        return jsonify({
            'success': True,
            'wallets': wallet_list
        })
        
    except Exception as e:
        logger.error(f"Admin get wallets error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get wallets'}), 500

@app.route('/api/admin/qr-logs', methods=['GET'])
@token_required
@admin_required
@rate_limit()
def admin_get_qr_logs():
    """Get QR code logs (admin only)"""
    try:
        db = get_db()
        qr_logs = db.execute('''
            SELECT q.id, q.user_id, q.wallet_address, q.amount, 
                   q.currency, q.status, q.created_at, u.email
            FROM qr_codes q
            JOIN users u ON q.user_id = u.id
            ORDER BY q.created_at DESC
            LIMIT 100
        ''').fetchall()
        
        qr_list = []
        for qr in qr_logs:
            qr_list.append({
                'id': str(qr['id']),
                'user_id': str(qr['user_id']),
                'user_email': qr['email'],
                'action': f"Generated QR for {qr['amount']} {qr['currency']}",
                'wallet_address': qr['wallet_address'],
                'amount': float(qr['amount']),
                'currency': qr['currency'],
                'status': qr['status'],
                'created_at': qr['created_at']
            })
        
        log_audit_event('admin@nomadpay.io', 'view_qr_logs', 'qr_codes', '', 'Viewed QR code logs')
        
        return jsonify({
            'success': True,
            'qr_logs': qr_list
        })
        
    except Exception as e:
        logger.error(f"Admin get QR logs error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get QR logs'}), 500

@app.route('/api/admin/security-logs', methods=['GET'])
@token_required
@admin_required
@rate_limit()
def admin_get_security_logs():
    """Get security logs (admin only)"""
    try:
        db = get_db()
        security_logs = db.execute('''
            SELECT id, user_id, event_type, ip_address, severity, details, created_at
            FROM security_logs
            ORDER BY created_at DESC
            LIMIT 100
        ''').fetchall()
        
        log_list = []
        for log in security_logs:
            log_list.append({
                'id': str(log['id']),
                'user_id': str(log['user_id']) if log['user_id'] else None,
                'event_type': log['event_type'],
                'ip_address': log['ip_address'],
                'severity': log['severity'],
                'details': log['details'],
                'created_at': log['created_at']
            })
        
        log_audit_event('admin@nomadpay.io', 'view_security_logs', 'security_logs', '', 'Viewed security logs')
        
        return jsonify({
            'success': True,
            'security_logs': log_list
        })
        
    except Exception as e:
        logger.error(f"Admin get security logs error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get security logs'}), 500

@app.route('/api/admin/audit-history', methods=['GET'])
@token_required
@admin_required
@rate_limit()
def admin_get_audit_history():
    """Get audit history (admin only)"""
    try:
        db = get_db()
        audit_logs = db.execute('''
            SELECT id, admin_user, action, resource_type, resource_id, 
                   details, ip_address, created_at
            FROM audit_logs
            ORDER BY created_at DESC
            LIMIT 100
        ''').fetchall()
        
        audit_list = []
        for audit in audit_logs:
            audit_list.append({
                'id': str(audit['id']),
                'admin_user': audit['admin_user'],
                'action': audit['action'],
                'resource_type': audit['resource_type'],
                'resource_id': audit['resource_id'],
                'details': audit['details'],
                'ip_address': audit['ip_address'],
                'created_at': audit['created_at']
            })
        
        log_audit_event('admin@nomadpay.io', 'view_audit_history', 'audit_logs', '', 'Viewed audit history')
        
        return jsonify({
            'success': True,
            'audit_logs': audit_list
        })
        
    except Exception as e:
        logger.error(f"Admin get audit history error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get audit history'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'success': False, 'message': 'Endpoint not found'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'success': False, 'message': 'Method not allowed'}), 405

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'success': False, 'message': 'Internal server error'}), 500

# Initialize database on startup
if __name__ == '__main__':
    try:
        init_db()
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port, debug=Config.DEBUG)
    except Exception as e:
        logger.error(f"Application startup failed: {e}")
        raise

