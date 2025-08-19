# 🌍 CultureQuest

**A comprehensive platform for cultural challenges, community engagement, and rewards management**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.3.3-green.svg)](https://flask.palletsprojects.com)

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Security](#security)
- [API Documentation](#api-documentation)
- [Contributing](#contributing)
- [License](#license)

## 🎯 Overview

CultureQuest is a full-featured web application that enables users to:
- Create and participate in cultural challenges
- Engage in real-time chat discussions
- Earn and redeem points through a rewards system
- Manage user accounts with Google OAuth integration
- Access AI-powered chatbot assistance

The platform is built with security-first principles and enterprise-grade features for scalability and reliability.

## ✨ Features

### 🏆 Challenge System
- **Create Custom Challenges**: Users can create challenges with descriptions, completion criteria, and media uploads
- **Admin Screening**: Administrative approval process for challenge submissions
- **File Upload Support**: Images and videos with security scanning via VirusTotal
- **Rate Limiting**: Prevents spam and abuse with configurable limits

### 💬 Real-Time Chat
- **Multiple Chat Rooms**: Dynamic room creation based on challenges
- **Security Features**: Content filtering, profanity detection, and user moderation
- **File Sharing**: Secure file uploads with malware scanning
- **Admin Controls**: User muting and message moderation

### 🎁 Rewards System
- **Points Management**: Users earn points through participation
- **Reward Catalog**: Configurable items with stock management
- **Redemption System**: Complete order processing with admin approval
- **Location Services**: Google Maps integration for pickup locations

### 🔐 Authentication & Security
- **Multi-Factor Authentication**: Email verification and Google OAuth
- **Session Management**: Secure session handling with Flask-Login
- **Rate Limiting**: Comprehensive protection against abuse
- **Security Headers**: HTTPS enforcement and CSP policies
- **Input Validation**: XSS and SQL injection prevention

### 🤖 AI Integration
- **Ollama Chatbot**: Integrated AI assistant for user support
- **Streaming Responses**: Real-time chat interface
- **Custom Models**: Configurable AI models for different use cases

### Technology Stack

**Backend:**
- **Flask** 2.3.3 - Web framework
- **SQLAlchemy** 2.0.23 - Database ORM
- **PyMySQL** 1.1.0 - MySQL driver
- **Flask-SocketIO** 5.3.6 - Real-time communication
- **Flask-Login** 0.6.3 - Session management

**Security:**
- **bcrypt** 4.1.2 - Password hashing
- **cryptography** 41.0.7 - Encryption utilities
- **bleach** 6.1.0 - XSS protection
- **secure** 0.3.0 - Security headers
- **pyotp** 2.9.0 - Two-factor authentication

**Integrations:**
- **Google OAuth** - Social authentication
- **VirusTotal API** - File security scanning
- **Ollama** - AI chatbot integration
- **Google Maps API** - Location services

## 🚀 Quick Start

### Prerequisites

- **Python** 3.11+
- **MySQL** 8.0+
- **Ollama** (optional, for AI chatbot)
- **Google OAuth Credentials** (optional, for social login)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd CultureQuest
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Initialize database:**
   ```bash
   python -c "from app import app, db; app.app_context().push(); db.create_all()"
   ```

6. **Run the application:**
   ```bash
   python app.py
   ```

Visit `https://localhost:5000` to access the application.

### Docker Deployment

```bash
# Build the container
docker build -t culturequest .

# Run with environment file
docker run -p 5000:5000 --env-file .env culturequest
```

## ⚙️ Configuration

### Required Environment Variables

```bash
# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=culturequest

# Security
SECRET_KEY=your-secret-key-here

# Google OAuth (Optional)
GOOGLE_OAUTH_CLIENT_ID=your-client-id
GOOGLE_OAUTH_CLIENT_SECRET=your-client-secret

# VirusTotal API (Optional)
VIRUSTOTAL_API_KEY=your-api-key

# Ollama AI (Optional)
OLLAMA_URL=http://localhost:11434

# reCAPTCHA (Optional)
RECAPTCHA_SITE_KEY=your-site-key
RECAPTCHA_SECRET_KEY=your-secret-key

# Google Maps (Optional)
GOOGLE_MAPS_API_KEY=your-maps-api-key
```



## 🔒 Security

CultureQuest implements comprehensive security measures:

### Authentication & Authorization
- **Multi-factor authentication** with email verification
- **Google OAuth integration** for social login
- **Role-based access control** (admin/user permissions)
- **Session security** with secure cookies

### Input Validation & Sanitization
- **XSS protection** via HTML sanitization with bleach
- **SQL injection prevention** with parameterized queries
- **File upload validation** with type and content checking
- **CSRF protection** with Flask-WTF tokens

### Security Monitoring
- **Rate limiting** on all sensitive endpoints
- **Security event logging** in `security_events.log`
- **Failed login attempt tracking**
- **Suspicious activity detection**

### Infrastructure Security
- **HTTPS enforcement** in production
- **Security headers** (CSP, HSTS, X-Frame-Options)
- **Database connection encryption**
- **Environment variable configuration**

## 📚 API Documentation

### Authentication Endpoints

- `POST /login` - User login
- `POST /signup` - User registration
- `GET /auth/google` - Google OAuth login
- `POST /logout` - User logout

### Challenge Endpoints

- `GET /host` - Challenge creation form
- `POST /host` - Submit new challenge
- `GET /admin/dashboard/screening` - Admin challenge approval
- `GET /event` - View challenges and events

### Chat Endpoints

- `GET /chat` - Chat room interface
- `POST /api/chatbot` - AI chatbot interaction
- WebSocket events: `join`, `leave`, `my event`

### Rewards Endpoints

- `GET /rewards` - Rewards catalog
- `POST /rewards/redeem/<item_id>` - Redeem reward
- `GET /rewards/admin` - Admin rewards management

## 🧪 Testing

```bash
# Run all tests
python -m pytest

# Security tests
python -m pytest tests/security/

# Integration tests
python -m pytest tests/integration/

# Check for vulnerabilities
pip audit
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow PEP 8 style guidelines
- Add security considerations for new features
- Include comprehensive tests
- Update documentation as needed
- Ensure all security checks pass

## 🔧 Troubleshooting

### Common Issues

**Database Connection Errors:**
- Verify MySQL is running and accessible
- Check database credentials in `.env`
- Ensure database exists and user has proper permissions

**OAuth Configuration:**
- Verify Google OAuth credentials are correct
- Check redirect URIs in Google Console
- Ensure HTTPS is configured for production

**File Upload Issues:**
- Check file permissions on upload directories
- Verify VirusTotal API key if using file scanning
- Ensure sufficient disk space

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

For technical support or feature requests:
- Create an issue in the repository
- Contact the development team
- Check the documentation wiki

---

**⚠️ Security Notice**: This application handles user data and file uploads. Ensure proper security configurations are in place before deploying to production environments.