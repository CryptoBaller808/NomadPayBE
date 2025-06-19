# NomadPay Backend API - FIXED Authentication

Production-ready Flask API with frontend-compatible authentication responses.

## 🔧 **CRITICAL FIXES IMPLEMENTED**

### **✅ Fixed Registration Response Structure**
- Removed `data: {}` wrapper
- Returns `access_token`, `refresh_token`, and `user` at root level
- Matches frontend expectations exactly

### **✅ Fixed Login Response Structure**  
- Changed field name from `token` to `access_token`
- Added `refresh_token` field
- Consistent response structure across all auth endpoints

### **✅ Enhanced Authentication System**
- JWT access tokens (1 hour expiry)
- JWT refresh tokens (7 days expiry)
- Secure token storage and management
- Comprehensive security logging

## 🚀 **API Endpoints**

### **Authentication**
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Token refresh
- `POST /api/auth/logout` - User logout

### **Wallet Management**
- `GET /api/wallet/balances` - Get wallet balances

### **Transactions**
- `GET /api/transactions` - Get transaction history
- `POST /api/transactions/send` - Send money

### **QR Codes**
- `POST /api/qr/generate` - Generate payment QR code

### **Admin**
- `GET /api/admin/users` - Get all users (admin only)

## 📦 **Installation**

```bash
pip install -r requirements.txt
python app.py
```

## 🔧 **Environment Variables**

```bash
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret
DATABASE_URL=nomadpay.db
PORT=5000
```

## 🌟 **Response Structure**

### **Registration/Login Response**
```json
{
  "success": true,
  "message": "Registration successful",
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "user": {
    "id": "1",
    "email": "user@example.com",
    "role": "user",
    "created_at": "2024-01-01T00:00:00"
  }
}
```

## 🛡️ **Security Features**

- Rate limiting on all endpoints
- JWT token authentication
- Password hashing with bcrypt
- Security event logging
- CORS configuration
- Input validation and sanitization

## 🎯 **Production Ready**

This backend is fully compatible with the NomadPay frontend and provides:
- Consistent API responses
- Comprehensive error handling
- Security best practices
- Scalable architecture

