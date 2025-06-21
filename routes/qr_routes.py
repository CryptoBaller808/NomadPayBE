"""
QR code routes
"""

from flask import Blueprint, jsonify

qr_bp = Blueprint('qr', __name__)

@qr_bp.route('/generate', methods=['POST'])
def generate_qr():
    """Generate QR code for payment"""
    return jsonify({
        'success': True,
        'qr_code': 'QR123456',
        'message': 'QR code generated successfully'
    }), 200

@qr_bp.route('/<code>', methods=['GET'])
def get_qr_details(code):
    """Get QR code details"""
    return jsonify({
        'success': True,
        'qr_code': code,
        'amount': 100.00,
        'currency': 'USD',
        'status': 'active'
    }), 200

