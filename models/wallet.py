"""
Wallet model for database operations
"""

import sqlite3
from config.database import get_db
from utils.logger import setup_logger

logger = setup_logger(__name__)

class Wallet:
    def __init__(self, id=None, user_id=None, currency=None, balance=0.0, created_at=None):
        self.id = id
        self.user_id = user_id
        self.currency = currency
        self.balance = balance
        self.created_at = created_at
    
    @staticmethod
    def create_default_wallets(user_id):
        """Create default wallets for a new user"""
        try:
            db = get_db()
            currencies = ['USD', 'EUR', 'BTC', 'ETH']
            
            for currency in currencies:
                initial_balance = 100.00 if currency in ['USD', 'EUR'] else 0.01
                db.execute('''
                    INSERT INTO wallets (user_id, currency, balance)
                    VALUES (?, ?, ?)
                ''', (user_id, currency, initial_balance))
            
            db.commit()
            logger.info(f"Default wallets created for user {user_id}")
            
        except sqlite3.Error as e:
            logger.error(f"Error creating default wallets: {e}")
            raise
    
    @staticmethod
    def get_user_wallets(user_id):
        """Get all wallets for a user"""
        try:
            db = get_db()
            wallets_data = db.execute('''
                SELECT id, user_id, currency, balance, created_at
                FROM wallets WHERE user_id = ?
                ORDER BY currency
            ''', (user_id,)).fetchall()
            
            wallets = []
            for wallet_data in wallets_data:
                wallets.append(Wallet(
                    id=wallet_data['id'],
                    user_id=wallet_data['user_id'],
                    currency=wallet_data['currency'],
                    balance=float(wallet_data['balance']),
                    created_at=wallet_data['created_at']
                ))
            
            return wallets
            
        except sqlite3.Error as e:
            logger.error(f"Error getting user wallets: {e}")
            raise
    
    def to_dict(self):
        """Convert wallet to dictionary"""
        return {
            'id': self.id,
            'currency': self.currency,
            'balance': self.balance,
            'created_at': self.created_at
        }

