"""
Security service for logging and monitoring
"""

import sqlite3
from datetime import datetime
from flask import request
from config.database import get_db
from utils.logger import setup_logger

logger = setup_logger(__name__)

class SecurityService:
    @staticmethod
    def log_security_event(event_type, severity, user_id=None, details=None):
        """Log security events"""
        try:
            db = get_db()
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get('User-Agent') if request else None
            
            db.execute('''
                INSERT INTO security_events 
                (user_id, event_type, severity, details, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, event_type, severity, details, ip_address, user_agent))
            
            db.commit()
            logger.info(f"Security event logged: {event_type} - {severity}")
            
        except sqlite3.Error as e:
            logger.error(f"Error logging security event: {e}")
    
    @staticmethod
    def get_security_events(limit=100):
        """Get recent security events"""
        try:
            db = get_db()
            events = db.execute('''
                SELECT se.*, u.email as user_email
                FROM security_events se
                LEFT JOIN users u ON se.user_id = u.id
                ORDER BY se.created_at DESC
                LIMIT ?
            ''', (limit,)).fetchall()
            
            return [dict(event) for event in events]
            
        except sqlite3.Error as e:
            logger.error(f"Error getting security events: {e}")
            return []

