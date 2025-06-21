"""
User model for database operations
"""

import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from config.database import get_db
from utils.logger import setup_logger

logger = setup_logger(__name__)

class User:
    def __init__(self, id=None, email=None, password_hash=None, role='user', status='active', created_at=None):
        self.id = id
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.status = status
        self.created_at = created_at
    
    @staticmethod
    def create(email, password, role='user'):
        """Create a new user"""
        try:
            db = get_db()
            password_hash = generate_password_hash(password)
            
            cursor = db.execute('''
                INSERT INTO users (email, password_hash, role, status)
                VALUES (?, ?, ?, ?)
            ''', (email.lower().strip(), password_hash, role, 'active'))
            
            user_id = cursor.lastrowid
            db.commit()
            
            logger.info(f"User created successfully: {email}")
            return user_id
            
        except sqlite3.Error as e:
            logger.error(f"Error creating user: {e}")
            raise
    
    @staticmethod
    def find_by_email(email):
        """Find user by email"""
        try:
            db = get_db()
            user_data = db.execute('''
                SELECT id, email, password_hash, role, status, created_at
                FROM users WHERE email = ?
            ''', (email.lower().strip(),)).fetchone()
            
            if user_data:
                return User(
                    id=user_data['id'],
                    email=user_data['email'],
                    password_hash=user_data['password_hash'],
                    role=user_data['role'],
                    status=user_data['status'],
                    created_at=user_data['created_at']
                )
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Error finding user by email: {e}")
            raise
    
    @staticmethod
    def find_by_id(user_id):
        """Find user by ID"""
        try:
            db = get_db()
            user_data = db.execute('''
                SELECT id, email, password_hash, role, status, created_at
                FROM users WHERE id = ?
            ''', (user_id,)).fetchone()
            
            if user_data:
                return User(
                    id=user_data['id'],
                    email=user_data['email'],
                    password_hash=user_data['password_hash'],
                    role=user_data['role'],
                    status=user_data['status'],
                    created_at=user_data['created_at']
                )
            return None
            
        except sqlite3.Error as e:
            logger.error(f"Error finding user by ID: {e}")
            raise
    
    def verify_password(self, password):
        """Verify user password"""
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': str(self.id),
            'email': self.email,
            'role': self.role,
            'status': self.status,
            'created_at': self.created_at
        }

