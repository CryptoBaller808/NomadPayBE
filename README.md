# NomadPay Backend API

Production-ready Flask backend API for the NomadPay digital financial platform.

## 🌟 Features

- **Complete Authentication System**: JWT-based auth with refresh tokens
- **Secure Financial Operations**: Wallet management and transactions
- **Admin Dashboard API**: Comprehensive admin endpoints
- **Security Intelligence**: Real-time security logging and audit trails
- **Rate Limiting**: Configurable rate limiting per endpoint
- **Database Management**: SQLite with comprehensive schema
- **Production Ready**: Gunicorn WSGI server with security headers

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip

### Installation
```bash
pip install -r requirements.txt
```

### Environment Setup
Copy `.env.example` to `.env` and configure:
```bash
cp .env.example .env
```

### Development
```bash
python app.py
```
Runs the API server on [http://localhost:5000](http://localhost:5000).

### Production
```bash
gunicorn --bind 0.0.0.0:$PORT app:app
```

## 🔧 Configuration

### Environment Variables
```env
SECRET_KEY=your_secret_key_here
JWT_SECRET_KEY=your_jwt_secret_key_here
DATABASE_URL=nomadpay.db
CORS_ORIGINS=*
RATE_LIMIT_PER_MINUTE=60
DEBUG=False
PORT=5000
```

## 📡 API Endpoints

### Authentication
- **POST /api/auth/register** - User registration
- **POST /api/auth/login** - User login
- **POST /api/auth/refresh** - Refresh access token
- **POST /api/auth/logout** - User logout

### Wallet Management
- **GET /api/wallet/balances** - Get user wallet balances

### Transactions
- **GET /api/transactions** - Get user transaction history
- **POST /api/transactions/send** - Send money transaction

### QR Codes
- **POST /api/qr/generate** - Generate payment QR code

### Admin Endpoints (Admin Role Required)
- **GET /api/admin/users** - Get all users
- **GET /api/admin/transactions** - Get all transactions
- **GET /api/admin/wallets** - Get all wallet balances
- **GET /api/admin/qr-logs** - Get QR code usage logs
- **GET /api/admin/security-logs** - Get security event logs
- **GET /api/admin/audit-history** - Get admin audit trail

### System
- **GET /api/health** - Health check endpoint

## 🔒 Security Features

### Authentication & Authorization
- **JWT Tokens**: Secure access and refresh token system
- **Password Hashing**: Werkzeug secure password hashing
- **Role-based Access**: User and admin role separation
- **Token Refresh**: Automatic token refresh mechanism
- **Session Management**: Secure session handling

### Security Headers
- **X-Content-Type-Options**: nosniff
- **X-Frame-Options**: DENY
- **X-XSS-Protection**: 1; mode=block
- **Strict-Transport-Security**: HSTS enabled
- **Content-Security-Policy**: CSP headers
- **Referrer-Policy**: strict-origin-when-cross-origin

### Rate Limiting
- **Configurable Limits**: Per-endpoint rate limiting
- **IP-based Tracking**: IP address rate limit tracking
- **Sliding Window**: 1-minute sliding window
- **Automatic Cleanup**: Expired rate limit cleanup

### Security Logging
- **Event Tracking**: Comprehensive security event logging
- **Severity Levels**: Critical, high, medium, low, info
- **IP Logging**: IP address and user agent tracking
- **Audit Trail**: Complete admin action audit trail

## 💾 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    status TEXT DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Wallets Table
```sql
CREATE TABLE wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    currency TEXT NOT NULL,
    balance DECIMAL(15,2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE(user_id, currency)
);
```

### Transactions Table
```sql
CREATE TABLE transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    currency TEXT NOT NULL,
    recipient TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Security Logs Table
```sql
CREATE TABLE security_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    event_type TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    severity TEXT DEFAULT 'info',
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## 🔄 API Response Format

### Success Response
```json
{
  "success": true,
  "message": "Operation successful",
  "data": { ... }
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error description"
}
```

## 🛡️ Security Events

### Event Types
- **user_registered**: New user registration
- **user_login**: Successful user login
- **login_failed**: Failed login attempt
- **token_refreshed**: Access token refreshed
- **user_logout**: User logout
- **transaction_sent**: Money transfer completed
- **qr_generated**: QR code generated
- **unauthorized_access**: Unauthorized API access
- **rate_limit_exceeded**: Rate limit exceeded
- **invalid_token**: Invalid token used

### Severity Levels
- **critical**: System-threatening events
- **high**: Security violations
- **medium**: Suspicious activities
- **low**: Minor security events
- **info**: Informational events

## 📊 Admin Features

### User Management
- **User Overview**: Complete user list with details
- **User Status**: Active/inactive user management
- **Registration Tracking**: User registration analytics

### Transaction Monitoring
- **Transaction History**: Complete transaction log
- **Volume Analytics**: Transaction volume tracking
- **Status Monitoring**: Transaction status oversight

### Security Monitoring
- **Real-time Logs**: Live security event monitoring
- **Threat Detection**: Anomaly detection and alerts
- **IP Tracking**: IP address monitoring
- **Audit Trail**: Complete admin action logging

### Data Export
- **CSV Export**: All data exportable to CSV
- **JSON Export**: Structured data export
- **Audit Reports**: Compliance audit reports

## 🚀 Deployment

### Production Setup
1. **Environment Configuration**
   ```bash
   export SECRET_KEY="your-production-secret-key"
   export JWT_SECRET_KEY="your-production-jwt-key"
   export DATABASE_URL="production-database-url"
   export CORS_ORIGINS="https://yourdomain.com"
   export DEBUG=False
   ```

2. **Database Initialization**
   ```bash
   python -c "from app import init_db; init_db()"
   ```

3. **Start Production Server**
   ```bash
   gunicorn --bind 0.0.0.0:$PORT --workers 4 app:app
   ```

### Docker Deployment
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
```

### Render.com Deployment
1. Connect GitHub repository
2. Set environment variables
3. Deploy with automatic builds

## 🧪 Testing

### API Testing
```bash
# Health check
curl http://localhost:5000/api/health

# User registration
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'

# User login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

### Load Testing
```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Test API performance
ab -n 1000 -c 10 http://localhost:5000/api/health
```

## 📈 Performance

### Optimization Features
- **Database Indexing**: Optimized database queries
- **Connection Pooling**: Efficient database connections
- **Caching**: Smart caching strategies
- **Rate Limiting**: Prevents API abuse

### Monitoring
- **Health Checks**: Built-in health monitoring
- **Error Logging**: Comprehensive error tracking
- **Performance Metrics**: Response time monitoring
- **Security Alerts**: Real-time security monitoring

## 🔧 Development

### Code Quality
- **Type Hints**: Python type annotations
- **Error Handling**: Comprehensive error handling
- **Logging**: Structured logging throughout
- **Documentation**: Inline code documentation

### Development Tools
- **Flask Debug Mode**: Development debugging
- **SQLite Browser**: Database inspection
- **Postman**: API testing
- **curl**: Command-line API testing

## 📚 Documentation

### API Documentation
- **Endpoint Reference**: Complete API endpoint documentation
- **Request/Response Examples**: Sample requests and responses
- **Error Codes**: HTTP status code reference
- **Authentication Guide**: JWT authentication documentation

### Database Documentation
- **Schema Reference**: Complete database schema
- **Relationship Diagrams**: Entity relationship documentation
- **Migration Guide**: Database migration instructions

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create feature branch
3. Implement API features
4. Add comprehensive tests
5. Submit pull request

### Code Standards
- **PEP 8**: Python code style compliance
- **Type Hints**: Use type annotations
- **Testing**: Include unit tests for new features
- **Documentation**: Update API documentation
- **Security**: Follow security best practices

## 📄 License

MIT License - see LICENSE file for details.

## 🌍 Global Deployment

### Multi-region Support
- **Global CDN**: Content delivery optimization
- **Database Replication**: Multi-region database support
- **Load Balancing**: Global load balancing
- **Monitoring**: Worldwide monitoring and alerting

### Scalability
- **Horizontal Scaling**: Multi-instance deployment
- **Database Scaling**: Database scaling strategies
- **Caching**: Redis caching for performance
- **Queue Systems**: Background job processing

---

**Enterprise-grade backend API for the global nomad financial platform**

*Secure, scalable, and production-ready* 🛡️🚀

