"""
Authentication service for JWT token management
"""

import jwt
import hashlib
from datetime import datetime, timedelta
from flask import current_app
from config.database import get_db
from utils.logger import setup_logger

logger = setup_logger(__name__)

class AuthService:
    @staticmethod
    def generate_tokens(user_id):
        """Generate access and refresh tokens"""
        try:
            # Access token (1 hour)
            access_payload = {
                'user_id': user_id,
                'type': 'access',
                'exp': datetime.utcnow() + timedelta(hours=1),
                'iat': datetime.utcnow()
            }
            
            access_token = jwt.encode(
                access_payload,
                current_app.config['JWT_SECRET_KEY'],
                algorithm='HS256'
            )
            
            # Refresh token (7 days)
            refresh_payload = {
                'user_id': user_id,
                'type': 'refresh',
                'exp': datetime.utcnow() + timedelta(days=7),
                'iat': datetime.utcnow()
            }
            
            refresh_token = jwt.encode(
                refresh_payload,
                current_app.config['JWT_SECRET_KEY'],
                algorithm='HS256'
            )
            
            # Store refresh token hash in database
            AuthService._store_refresh_token(user_id, refresh_token)
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token
            }
            
        except Exception as e:
            logger.error(f"Error generating tokens: {e}")
            raise
    
    @staticmethod
    def _store_refresh_token(user_id, refresh_token):
        """Store refresh token hash in database"""
        try:
            db = get_db()
            token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
            expires_at = datetime.utcnow() + timedelta(days=7)
            
            db.execute('''
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
                VALUES (?, ?, ?)
            ''', (user_id, token_hash, expires_at))
            
            db.commit()
            
        except Exception as e:
            logger.error(f"Error storing refresh token: {e}")
            raise
    
    @staticmethod
    def verify_token(token, token_type='access'):
        """Verify JWT token"""
        try:
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            
            if payload.get('type') != token_type:
                return None
                
            return payload
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    @staticmethod
    def revoke_refresh_token(refresh_token):
        """Revoke a refresh token"""
        try:
            db = get_db()
            token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
            
            db.execute('''
                UPDATE refresh_tokens 
                SET revoked = TRUE 
                WHERE token_hash = ?
            ''', (token_hash,))
            
            db.commit()
            
        except Exception as e:
            logger.error(f"Error revoking refresh token: {e}")
            raise

