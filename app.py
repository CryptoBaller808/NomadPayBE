#!/usr/bin/env python3
"""
NomadPay Backend API - Complete MVC Architecture
Main application entry point with proper folder structure.
"""

import os
from flask import Flask
from flask_cors import CORS
from config.database import init_db
from routes.auth_routes import auth_bp
from routes.wallet_routes import wallet_bp
from routes.transaction_routes import transaction_bp
from routes.qr_routes import qr_bp
from routes.admin_routes import admin_bp
from routes.system_routes import system_bp
from utils.logger import setup_logger

# Initialize logger
logger = setup_logger(__name__)

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'nomadpay-secret-key-2024')
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'nomadpay-jwt-secret-2024')
    app.config['DATABASE_URL'] = os.environ.get('DATABASE_URL', 'nomadpay.db')
    
    # CORS configuration for production
    CORS(app, origins=[
        'https://nomadpay-frontend.onrender.com',
        'https://nomadpayadmin.onrender.com',
        'https://tpfviivg.manus.space',
        'https://vkpxlfov.manus.space',
        'http://localhost:3000',
        'http://localhost:3001'
    ], supports_credentials=True)
    
    # Initialize database
    with app.app_context():
        init_db()
    
    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(wallet_bp, url_prefix='/api/wallet')
    app.register_blueprint(transaction_bp, url_prefix='/api/transactions')
    app.register_blueprint(qr_bp, url_prefix='/api/qr')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')
    app.register_blueprint(system_bp, url_prefix='/api')
    
    logger.info("NomadPay Backend API initialized successfully")
    return app

# Create app instance
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

