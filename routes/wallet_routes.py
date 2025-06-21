"""
Wallet routes
"""

from flask import Blueprint, jsonify
from models.wallet import Wallet
from utils.auth_middleware import require_auth

wallet_bp = Blueprint('wallet', __name__)

@wallet_bp.route('/balances', methods=['GET'])
@require_auth
def get_balances(current_user):
    """Get user wallet balances"""
    try:
        wallets = Wallet.get_user_wallets(current_user.id)
        wallet_data = [wallet.to_dict() for wallet in wallets]
        
        return jsonify({
            'success': True,
            'wallets': wallet_data
        }), 200
        
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to get wallet balances'}), 500

