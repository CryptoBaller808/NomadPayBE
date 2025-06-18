from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import uuid
import time
from datetime import datetime, timedelta
import jwt
import hashlib
import json

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'nomadpay-secret-key-2025')
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'nomadpay-jwt-secret-2025')

# In-memory storage (replace with database in production)
users_db = {}
transactions_db = {}
wallets_db = {}
sessions_db = {}

# Helper functions
def generate_jwt_token(user_id):
    """Generate JWT token for user authentication"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')

def verify_jwt_token(token):
    """Verify JWT token and return user_id"""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def hash_password(password):
    """Hash password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def init_user_wallet(user_id):
    """Initialize wallet for new user"""
    wallets_db[user_id] = {
        'USD': {'balance': 1000.00, 'address': f'usd_{user_id[:8]}'},
        'EUR': {'balance': 850.00, 'address': f'eur_{user_id[:8]}'},
        'BTC': {'balance': 0.025, 'address': f'bc1q{user_id[:20]}'},
        'ETH': {'balance': 0.85, 'address': f'0x{user_id[:40]}'},
    }

# Authentication endpoints
@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        name = data.get('name', 'NomadPay User')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        if email in users_db:
            return jsonify({'error': 'User already exists'}), 409
        
        user_id = str(uuid.uuid4())
        users_db[email] = {
            'id': user_id,
            'email': email,
            'name': name,
            'password': hash_password(password),
            'created_at': datetime.utcnow().isoformat(),
            'verified': True,  # Auto-verify for demo
            'two_factor_enabled': False
        }
        
        # Initialize user wallet
        init_user_wallet(user_id)
        
        # Generate token
        token = generate_jwt_token(user_id)
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'user': {
                'id': user_id,
                'email': email,
                'name': name,
                'verified': True
            },
            'token': token
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        user = users_db.get(email)
        if not user or user['password'] != hash_password(password):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        # Generate token
        token = generate_jwt_token(user['id'])
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'verified': user['verified']
            },
            'token': token
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/profile', methods=['GET'])
def get_profile():
    """Get user profile"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Find user by ID
        user = None
        for email, user_data in users_db.items():
            if user_data['id'] == user_id:
                user = user_data
                user['email'] = email
                break
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'success': True,
            'user': {
                'id': user['id'],
                'email': user['email'],
                'name': user['name'],
                'verified': user['verified'],
                'two_factor_enabled': user['two_factor_enabled']
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Wallet endpoints
@app.route('/api/wallet/balances', methods=['GET'])
def get_wallet_balances():
    """Get user wallet balances"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        wallet = wallets_db.get(user_id, {})
        
        return jsonify({
            'success': True,
            'balances': wallet
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/wallet/addresses', methods=['GET'])
def get_wallet_addresses():
    """Get user wallet addresses"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        wallet = wallets_db.get(user_id, {})
        addresses = {currency: data['address'] for currency, data in wallet.items()}
        
        return jsonify({
            'success': True,
            'addresses': addresses
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Transaction endpoints
@app.route('/api/transactions/send', methods=['POST'])
def send_money():
    """Send money transaction"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        data = request.get_json()
        recipient = data.get('recipient')
        amount = float(data.get('amount', 0))
        currency = data.get('currency', 'USD')
        description = data.get('description', '')
        
        if not recipient or amount <= 0:
            return jsonify({'error': 'Valid recipient and amount required'}), 400
        
        # Check balance
        user_wallet = wallets_db.get(user_id, {})
        if currency not in user_wallet or user_wallet[currency]['balance'] < amount:
            return jsonify({'error': 'Insufficient balance'}), 400
        
        # Create transaction
        transaction_id = str(uuid.uuid4())
        transaction = {
            'id': transaction_id,
            'type': 'send',
            'sender_id': user_id,
            'recipient': recipient,
            'amount': amount,
            'currency': currency,
            'description': description,
            'status': 'completed',
            'fee': amount * 0.005,  # 0.5% fee
            'timestamp': datetime.utcnow().isoformat(),
            'tx_hash': f'0x{transaction_id.replace("-", "")[:40]}'
        }
        
        # Update balance
        user_wallet[currency]['balance'] -= (amount + transaction['fee'])
        transactions_db[transaction_id] = transaction
        
        return jsonify({
            'success': True,
            'message': 'Transaction completed successfully',
            'transaction': transaction
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions/history', methods=['GET'])
def get_transaction_history():
    """Get user transaction history"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Filter transactions for this user
        user_transactions = []
        for tx_id, tx in transactions_db.items():
            if tx.get('sender_id') == user_id or tx.get('recipient_id') == user_id:
                user_transactions.append(tx)
        
        # Sort by timestamp (newest first)
        user_transactions.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'success': True,
            'transactions': user_transactions
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# QR Code endpoints
@app.route('/api/qr/generate', methods=['POST'])
def generate_qr_data():
    """Generate QR code data for payments"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        data = request.get_json()
        amount = data.get('amount')
        currency = data.get('currency', 'USD')
        description = data.get('description', '')
        
        # Get user wallet address
        user_wallet = wallets_db.get(user_id, {})
        if currency not in user_wallet:
            return jsonify({'error': 'Currency not supported'}), 400
        
        address = user_wallet[currency]['address']
        
        # Generate QR data
        qr_data = f"nomadpay://pay?to={address}&amount={amount}&currency={currency}&description={description}"
        
        return jsonify({
            'success': True,
            'qr_data': qr_data,
            'address': address,
            'amount': amount,
            'currency': currency,
            'description': description
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Analytics endpoints
@app.route('/api/analytics/dashboard', methods=['GET'])
def get_dashboard_analytics():
    """Get dashboard analytics"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authorization token required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Calculate user analytics
        user_transactions = [tx for tx in transactions_db.values() if tx.get('sender_id') == user_id]
        
        total_sent = sum(tx['amount'] for tx in user_transactions if tx['type'] == 'send')
        total_fees = sum(tx['fee'] for tx in user_transactions)
        transaction_count = len(user_transactions)
        
        # Get wallet total value (in USD equivalent)
        user_wallet = wallets_db.get(user_id, {})
        total_balance_usd = user_wallet.get('USD', {}).get('balance', 0)
        
        return jsonify({
            'success': True,
            'analytics': {
                'total_balance_usd': total_balance_usd,
                'total_sent': total_sent,
                'total_fees': total_fees,
                'transaction_count': transaction_count,
                'currencies_count': len(user_wallet),
                'last_transaction': user_transactions[0]['timestamp'] if user_transactions else None
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'NomadPay Backend API',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    }), 200

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    """Root endpoint"""
    return jsonify({
        'message': 'Welcome to NomadPay Backend API',
        'version': '1.0.0',
        'endpoints': {
            'auth': '/api/auth/*',
            'wallet': '/api/wallet/*',
            'transactions': '/api/transactions/*',
            'qr': '/api/qr/*',
            'analytics': '/api/analytics/*',
            'health': '/health'
        }
    }), 200

if __name__ == '__main__':
    # Initialize demo data
    demo_user_id = str(uuid.uuid4())
    users_db['demo@nomadpay.io'] = {
        'id': demo_user_id,
        'email': 'demo@nomadpay.io',
        'name': 'Demo User',
        'password': hash_password('demo123'),
        'created_at': datetime.utcnow().isoformat(),
        'verified': True,
        'two_factor_enabled': False
    }
    init_user_wallet(demo_user_id)
    
    # Add demo transaction
    demo_tx_id = str(uuid.uuid4())
    transactions_db[demo_tx_id] = {
        'id': demo_tx_id,
        'type': 'send',
        'sender_id': demo_user_id,
        'recipient': 'friend@example.com',
        'amount': 100.0,
        'currency': 'USD',
        'description': 'Coffee payment',
        'status': 'completed',
        'fee': 0.5,
        'timestamp': datetime.utcnow().isoformat(),
        'tx_hash': f'0x{demo_tx_id.replace("-", "")[:40]}'
    }
    
    print("🚀 Starting NomadPay Backend API...")
    print("📊 Demo user: demo@nomadpay.io / demo123")
    print("🌐 Server running on http://0.0.0.0:5000")
    
    app.run(host='0.0.0.0', port=5000, debug=False)

