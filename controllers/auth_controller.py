"""
Authentication controller with FIXED response structure
"""

from flask import request, jsonify
from models.user import User
from models.wallet import Wallet
from services.auth_service import AuthService
from services.security_service import SecurityService
from utils.logger import setup_logger

logger = setup_logger(__name__)

class AuthController:
    @staticmethod
    def register():
        """User registration with FIXED response structure"""
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
            
            # Check if user exists
            existing_user = User.find_by_email(email)
            if existing_user:
                SecurityService.log_security_event('registration_attempt_existing_email', 'low', details=f'Email: {email}')
                return jsonify({'success': False, 'message': 'Email already registered'}), 409
            
            # Create user
            user_id = User.create(email, password)
            
            # Create default wallets
            Wallet.create_default_wallets(user_id)
            
            # Generate tokens
            tokens = AuthService.generate_tokens(user_id)
            
            SecurityService.log_security_event('user_registered', 'info', user_id, f'New user registered: {email}')
            
            # ✅ FIXED: Return response structure that matches frontend expectations
            response_data = {
                'success': True,
                'message': 'Registration successful',
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token'],
                'user': {
                    'id': str(user_id),
                    'email': email,
                    'role': 'user',
                    'created_at': '2024-01-01T00:00:00'
                }
            }
            
            logger.info(f"User registered successfully: {email}")
            return jsonify(response_data), 201
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return jsonify({'success': False, 'message': 'Registration failed. Please try again.'}), 500
    
    @staticmethod
    def login():
        """User login with FIXED response structure"""
        try:
            data = request.get_json()
            if not data:
                return jsonify({'success': False, 'message': 'No data provided'}), 400
                
            email = data.get('email', '').lower().strip()
            password = data.get('password', '')
            
            if not email or not password:
                return jsonify({'success': False, 'message': 'Email and password are required'}), 400
            
            # Find user
            user = User.find_by_email(email)
            if not user or not user.verify_password(password):
                SecurityService.log_security_event('failed_login_attempt', 'medium', details=f'Email: {email}')
                return jsonify({'success': False, 'message': 'Invalid email or password'}), 401
            
            if user.status != 'active':
                SecurityService.log_security_event('inactive_user_login_attempt', 'medium', user.id, f'Inactive user login: {email}')
                return jsonify({'success': False, 'message': 'Account is not active'}), 401
            
            # Generate tokens
            tokens = AuthService.generate_tokens(user.id)
            
            SecurityService.log_security_event('user_login', 'info', user.id, f'User logged in: {email}')
            
            # ✅ FIXED: Return response structure that matches frontend expectations
            response_data = {
                'success': True,
                'message': 'Login successful',
                'access_token': tokens['access_token'],  # ✅ Changed from 'token' to 'access_token'
                'refresh_token': tokens['refresh_token'], # ✅ Added refresh_token
                'user': user.to_dict()
            }
            
            logger.info(f"User logged in successfully: {email}")
            return jsonify(response_data), 200
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'success': False, 'message': 'Login failed. Please try again.'}), 500
    
    @staticmethod
    def refresh():
        """Refresh access token"""
        try:
            data = request.get_json()
            refresh_token = data.get('refresh_token') if data else None
            
            if not refresh_token:
                return jsonify({'success': False, 'message': 'Refresh token required'}), 400
            
            # Verify refresh token
            payload = AuthService.verify_token(refresh_token, 'refresh')
            if not payload:
                return jsonify({'success': False, 'message': 'Invalid or expired refresh token'}), 401
            
            user_id = payload['user_id']
            
            # Generate new tokens
            tokens = AuthService.generate_tokens(user_id)
            
            # Revoke old refresh token
            AuthService.revoke_refresh_token(refresh_token)
            
            response_data = {
                'success': True,
                'message': 'Token refreshed successfully',
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
            
            return jsonify(response_data), 200
            
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return jsonify({'success': False, 'message': 'Token refresh failed'}), 500
    
    @staticmethod
    def logout():
        """User logout"""
        try:
            data = request.get_json()
            refresh_token = data.get('refresh_token') if data else None
            
            if refresh_token:
                AuthService.revoke_refresh_token(refresh_token)
            
            return jsonify({'success': True, 'message': 'Logged out successfully'}), 200
            
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return jsonify({'success': False, 'message': 'Logout failed'}), 500

