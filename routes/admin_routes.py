"""
Admin routes
"""

from flask import Blueprint, jsonify
from services.security_service import SecurityService

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/users', methods=['GET'])
def get_users():
    """Get all users"""
    return jsonify({
        'success': True,
        'users': [],
        'message': 'Users retrieved successfully'
    }), 200

@admin_bp.route('/transactions', methods=['GET'])
def get_all_transactions():
    """Get all transactions"""
    return jsonify({
        'success': True,
        'transactions': [],
        'message': 'Transactions retrieved successfully'
    }), 200

@admin_bp.route('/security-events', methods=['GET'])
def get_security_events():
    """Get security events"""
    try:
        events = SecurityService.get_security_events()
        return jsonify({
            'success': True,
            'events': events,
            'message': 'Security events retrieved successfully'
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to get security events'}), 500

@admin_bp.route('/analytics', methods=['GET'])
def get_analytics():
    """Get platform analytics"""
    return jsonify({
        'success': True,
        'analytics': {
            'total_users': 0,
            'total_transactions': 0,
            'total_volume': 0
        },
        'message': 'Analytics retrieved successfully'
    }), 200

