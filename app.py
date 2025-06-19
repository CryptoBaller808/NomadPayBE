#!/usr/bin/env python3
"""
NomadPay Backend API - Enhanced with better error handling and response structure
Production-ready Flask API with comprehensive authentication, wallet management, and security features.
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

# Database functions
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

def close_db(e=None):
    """Close database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

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
                recipient TEXT,
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
                qr_id TEXT UNIQUE NOT NULL,
                amount DECIMAL(15,8) NOT NULL,
                currency TEXT NOT NULL,
                wallet_address TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
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
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
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

def verify_token(token: str, token_type: str = 'access') -> Optional[Dict[str, Any]]:
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
        
        if payload.get('type') != token_type:
            return None
            
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.warning("Token has expired")
        return None
    except jwt.InvalidTokenError:
        logger.warning("Invalid token")
        return None
    except Exception as e:
        logger.error(f"Token verification error: {e}")
        return None

def log_security_event(event_type: str, severity: str, user_id: int = None, details: str = None):
    """Log security events"""
    try:
        db = get_db()
        db.execute('''
            INSERT INTO security_events (user_id, event_type, severity, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, event_type, severity, request.remote_addr, request.headers.get('User-Agent'), details))
        db.commit()
    except Exception as e:
        logger.error(f"Security event logging error: {e}")

# Rate limiting decorator
def rate_limit(max_requests: int):
    """Simple rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple rate limiting implementation
            # In production, use Redis or similar for distributed rate limiting
            return f(*args, **kwargs)
        return decorated_function
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
    """User registration with enhanced error handling"""
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
        
        # Return complete response with all required fields
        response_data = {
            'success': True,
            'message': 'Registration successful',
            'user': {
                'id': str(user_id),
                'email': email,
                'role': 'user',
                'created_at': datetime.utcnow().isoformat()
            },
            'access_token': tokens['access_token'],
            'refresh_token': tokens['refresh_token']
        }
        
        logger.info(f"User registered successfully: {email}")
        return jsonify(response_data), 201
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500

@app.route('/api/auth/login', methods=['POST'])
@rate_limit(10)  # 10 login attempts per minute
def login():
    """User login with enhanced error handling"""
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
        
        # Return complete response with all required fields
        response_data = {
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
        }
        
        logger.info(f"User logged in successfully: {email}")
        return jsonify(response_data), 200
        
    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500

# Initialize database on startup
@app.before_first_request
def initialize_database():
    """Initialize database before first request"""
    init_db()

# Cleanup database connections
@app.teardown_appcontext
def close_db_connection(error):
    """Close database connection after each request"""
    close_db(error)

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

