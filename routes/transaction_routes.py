"""
Transaction routes
"""

from flask import Blueprint, jsonify

transaction_bp = Blueprint('transactions', __name__)

@transaction_bp.route('/', methods=['GET'])
def get_transactions():
    """Get transaction history"""
    return jsonify({
        'success': True,
        'transactions': [],
        'message': 'Transaction history retrieved successfully'
    }), 200

@transaction_bp.route('/send', methods=['POST'])
def send_transaction():
    """Send money transaction"""
    return jsonify({
        'success': True,
        'message': 'Transaction sent successfully',
        'transaction_id': 'tx_123456'
    }), 200

