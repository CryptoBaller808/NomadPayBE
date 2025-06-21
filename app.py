"""
NomadPay Backend API - Main Application
Fixed version with correct authentication response structure
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import logging
from datetime import datetime

# Import controllers and routes
from controllers.auth_controller import AuthController

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configure CORS for production
CORS(app, origins=[
    'https://nomadpay-frontend.onrender.com',
    'https://nomadpayadmin.onrender.com',
    'http://localhost:3000',
    'http://localhost:3001'
])

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'nomadpay.db')

# Initialize controllers
auth_controller = AuthController(
    db_path=app.config['DATABASE_URL'],
    secret_key=app.config['SECRET_KEY']
)

# Health check endpoint
@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'NomadPay Backend API',
        'version': '1.0.0',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

# Root endpoint with API information
@app.route('/', methods=['GET'])
def root():
    """Root endpoint with API information"""
    return jsonify({
        'message': 'Welcome to NomadPay Backend API',
        'version': '1.0.0',
        'endpoints': {
            'health': '/api/health',
            'auth': '/api/auth/**',
            'wallet': '/api/wallet/**',
            'transactions': '/api/transactions/**',
            'qr': '/api/qr/**',
            'analytics': '/api/analytics/**'
        }
    }), 200

# Authentication routes with FIXED response structure
@app.route('/api/auth/register', methods=['POST'])
def register():
    """User registration endpoint"""
    return auth_controller.register()

@app.route('/api/auth/login', methods=['POST'])
def login():
    """User login endpoint"""
    return auth_controller.login()

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Token refresh endpoint"""
    return auth_controller.refresh_token()

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    return auth_controller.logout()

# Wallet endpoints (mock implementations for now)
@app.route('/api/wallet/balances', methods=['GET'])
def get_wallet_balances():
    """Get wallet balances"""
    return jsonify({
        'success': True,
        'balances': {
            'USD': 1250.00,
            'EUR': 890.50,
            'BTC': 0.05432,
            'ETH': 2.1234
        }
    }), 200

@app.route('/api/wallet/history', methods=['GET'])
def get_wallet_history():
    """Get wallet transaction history"""
    return jsonify({
        'success': True,
        'transactions': [
            {
                'id': '1',
                'type': 'receive',
                'amount': 500.00,
                'currency': 'USD',
                'from': 'john@example.com',
                'date': '2024-01-15T10:30:00Z'
            },
            {
                'id': '2',
                'type': 'send',
                'amount': 250.00,
                'currency': 'EUR',
                'to': 'sarah@example.com',
                'date': '2024-01-14T15:45:00Z'
            }
        ]
    }), 200

# Transaction endpoints
@app.route('/api/transactions/send', methods=['POST'])
def send_transaction():
    """Send money transaction"""
    data = request.get_json()
    return jsonify({
        'success': True,
        'message': 'Transaction sent successfully',
        'transaction_id': 'tx_' + str(datetime.utcnow().timestamp()),
        'amount': data.get('amount', 0),
        'currency': data.get('currency', 'USD'),
        'recipient': data.get('recipient', '')
    }), 200

@app.route('/api/transactions/history', methods=['GET'])
def get_transaction_history():
    """Get transaction history"""
    return jsonify({
        'success': True,
        'transactions': [
            {
                'id': 'tx_1',
                'type': 'send',
                'amount': 100.00,
                'currency': 'USD',
                'recipient': 'alice@example.com',
                'status': 'completed',
                'date': '2024-01-15T12:00:00Z'
            },
            {
                'id': 'tx_2',
                'type': 'receive',
                'amount': 75.50,
                'currency': 'EUR',
                'sender': 'bob@example.com',
                'status': 'completed',
                'date': '2024-01-14T18:30:00Z'
            }
        ]
    }), 200

# QR Code endpoints
@app.route('/api/qr/generate', methods=['POST'])
def generate_qr():
    """Generate QR code for payment"""
    data = request.get_json()
    return jsonify({
        'success': True,
        'qr_code': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
        'qr_data': {
            'amount': data.get('amount', 0),
            'currency': data.get('currency', 'USD'),
            'recipient': data.get('recipient', ''),
            'expires_at': '2024-01-16T12:00:00Z'
        }
    }), 200

@app.route('/api/qr/scan', methods=['POST'])
def scan_qr():
    """Process scanned QR code"""
    data = request.get_json()
    return jsonify({
        'success': True,
        'message': 'QR code processed successfully',
        'payment_data': {
            'amount': 50.00,
            'currency': 'USD',
            'recipient': 'merchant@example.com',
            'description': 'Coffee purchase'
        }
    }), 200

# Admin endpoints (basic implementations)
@app.route('/api/admin/users', methods=['GET'])
def get_admin_users():
    """Get users for admin dashboard"""
    return jsonify({
        'success': True,
        'users': [
            {
                'id': '1',
                'email': 'testuser2025@nomadpay.io',
                'role': 'user',
                'status': 'active',
                'created_at': '2024-01-15T10:00:00Z'
            }
        ],
        'total': 1
    }), 200

@app.route('/api/admin/transactions', methods=['GET'])
def get_admin_transactions():
    """Get transactions for admin dashboard"""
    return jsonify({
        'success': True,
        'transactions': [
            {
                'id': 'tx_1',
                'user_email': 'testuser2025@nomadpay.io',
                'type': 'send',
                'amount': 100.00,
                'currency': 'USD',
                'status': 'completed',
                'created_at': '2024-01-15T12:00:00Z'
            }
        ],
        'total': 1
    }), 200

@app.route('/api/admin/analytics', methods=['GET'])
def get_admin_analytics():
    """Get analytics for admin dashboard"""
    return jsonify({
        'success': True,
        'analytics': {
            'total_users': 1,
            'total_transactions': 1,
            'total_volume': 100.00,
            'active_users_today': 1
        }
    }), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'message': 'Endpoint not found'
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({
        'success': False,
        'message': 'Method not allowed'
    }), 405

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'message': 'Internal server error'
    }), 500

# Run the application
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    logger.info(f"Starting NomadPay Backend API on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)

