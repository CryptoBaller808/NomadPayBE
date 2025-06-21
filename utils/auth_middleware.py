"""
Authentication middleware
"""

from functools import wraps
from flask import request, jsonify
from services.auth_service import AuthService
from models.user import User

def require_auth(f):
    """Authentication required decorator"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        payload = AuthService.verify_token(token)
        
        if not payload:
            return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401
        
        current_user = User.find_by_id(payload['user_id'])
        if not current_user:
            return jsonify({'success': False, 'message': 'User not found'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated_function

