"""
System routes
"""

from flask import Blueprint, jsonify

system_bp = Blueprint('system', __name__)

@system_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'message': 'NomadPay Backend API is running',
        'version': '1.0.0'
    }), 200

@system_bp.route('/', methods=['GET'])
def api_info():
    """API information endpoint"""
    return jsonify({
        'name': 'NomadPay Backend API',
        'version': '1.0.0',
        'description': 'Digital nomad financial platform API',
        'status': 'operational'
    }), 200

