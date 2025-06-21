"""
Authentication routes
"""

from flask import Blueprint
from controllers.auth_controller import AuthController
from utils.rate_limiter import rate_limit

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@rate_limit(5)  # 5 registration attempts per minute
def register():
    """User registration endpoint"""
    return AuthController.register()

@auth_bp.route('/login', methods=['POST'])
@rate_limit(10)  # 10 login attempts per minute
def login():
    """User login endpoint"""
    return AuthController.login()

@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    """Token refresh endpoint"""
    return AuthController.refresh()

@auth_bp.route('/logout', methods=['POST'])
def logout():
    """User logout endpoint"""
    return AuthController.logout()

