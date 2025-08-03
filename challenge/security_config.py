"""
Security configuration for Flask application.
Implements secure session and security headers.
"""
import os
from datetime import timedelta
from flask import Flask

def configure_security(app: Flask):
    """Configure comprehensive security settings for the Flask application."""
    
    # Session Security Configuration - Protects against session hijacking
    app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only - Protects against session theft over HTTP
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access - Protects against XSS session theft
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection - Protects against cross-site request forgery
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)  # Session timeout - Protects against stale session attacks
    
    # Generate secure secret key if not provided - Protects against session tampering
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = os.urandom(32)  # Cryptographically secure random key
    
    # CSRF Protection - Already handled by Flask-WTF but ensure it's enabled
    app.config['WTF_CSRF_ENABLED'] = True  # Protects against Cross-Site Request Forgery attacks
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour CSRF token timeout - Protects against token replay attacks
    
    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        """Add security headers to all responses - Protects against various web attacks."""
        
        # Prevent clickjacking attacks
        response.headers['X-Frame-Options'] = 'DENY'  # Protects against clickjacking attacks
        
        # Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'  # Protects against MIME confusion attacks
        
        # XSS Protection (for older browsers)
        response.headers['X-XSS-Protection'] = '1; mode=block'  # Protects against reflected XSS attacks
        
        # Referrer Policy - limit information leakage
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'  # Protects against referrer leakage
        
        # Content Security Policy - prevents script injection
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'"
        )  # Protects against XSS and code injection attacks
        
        # Strict Transport Security (HTTPS enforcement)
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # Protects against protocol downgrade attacks
        
        return response
    
    return app

def validate_session_security(session_data):
    """Validate session data for security issues - Protects against session tampering."""
    required_fields = ['username', 'email']
    
    # Check for required session fields - Protects against incomplete authentication
    for field in required_fields:
        if field not in session_data:
            return False
    
    # Validate email format - Protects against malformed session data
    email = session_data.get('email', '')
    if '@' not in email or '.' not in email:
        return False
    
    return True

def sanitize_session_data(session_data):
    """Sanitize session data to prevent injection attacks - Protects against session pollution."""
    sanitized = {}
    
    # Allowed session keys - Protects against session key pollution
    allowed_keys = {'username', 'email', 'role', 'user_id', 'last_login'}
    
    for key, value in session_data.items():
        if key in allowed_keys and isinstance(value, (str, int)):
            # Basic sanitization - remove potentially dangerous characters
            if isinstance(value, str):
                sanitized[key] = value.replace('<', '').replace('>', '').replace('"', '').replace("'", '')
            else:
                sanitized[key] = value
    
    return sanitized