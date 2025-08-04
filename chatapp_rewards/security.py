"""
Comprehensive Security Module for CultureQuest ChatApp Rewards
===========================================================

This module implements security measures based on static analysis findings:

IDENTIFIED VULNERABILITIES:
1. SQL Injection risks in multiple endpoints
2. XSS vulnerabilities in template rendering
3. CSRF attacks on state-changing operations
4. Input validation gaps
5. File upload security issues
6. Session management weaknesses
7. Rate limiting absence
8. Information disclosure through error messages
9. Missing security headers
10. Insufficient access control validation

SECURITY MEASURES IMPLEMENTED:
- Input sanitization and validation
- CSRF protection
- XSS prevention
- SQL injection prevention
- Rate limiting
- Secure file handling
- Enhanced error handling
- Security headers
- Session security
- Access control validation
"""

import re
import hashlib
import hmac
import time
import json
import logging
import secrets
from typing import Any, Dict, List, Optional, Union, Tuple
from functools import wraps
from datetime import datetime, timedelta
from flask import request, session, jsonify, current_app, g
from werkzeug.exceptions import BadRequest, Forbidden, TooManyRequests
from sqlalchemy import text
from markupsafe import Markup, escape

# Configure security logging
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# Security configuration
SECURITY_CONFIG = {
    'MAX_REQUEST_SIZE': 50 * 1024 * 1024,  # 50MB
    'MAX_FILE_SIZE': 10 * 1024 * 1024,     # 10MB  
    'MAX_MESSAGE_LENGTH': 2000,             # Characters
    'MAX_USERNAME_LENGTH': 50,              # Characters
    'MAX_ROOM_NAME_LENGTH': 100,           # Characters
    'RATE_LIMIT_PER_MINUTE': 60,           # Requests per minute
    'RATE_LIMIT_PER_HOUR': 1000,           # Requests per hour
    'SESSION_TIMEOUT': 24 * 60 * 60,       # 24 hours in seconds
    'CSRF_TOKEN_EXPIRY': 60 * 60,          # 1 hour in seconds
    'ALLOWED_EXTENSIONS': {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'},
    'BLOCKED_EXTENSIONS': {'exe', 'bat', 'cmd', 'com', 'pif', 'scr', 'vbs', 'js', 'jar', 'php', 'asp', 'aspx'},
    'MAX_LOGIN_ATTEMPTS': 5,               # Per IP address
    'LOGIN_LOCKOUT_TIME': 15 * 60,         # 15 minutes
}

# Rate limiting storage (in production, use Redis)
rate_limit_store = {}
login_attempts = {}

class SecurityViolation(Exception):
    """Custom exception for security violations"""
    def __init__(self, message: str, violation_type: str = "UNKNOWN", severity: str = "MEDIUM"):
        self.message = message
        self.violation_type = violation_type
        self.severity = severity
        super().__init__(message)

class InputValidator:
    """Input validation and sanitization utilities"""
    
    @staticmethod
    def validate_string(value: Any, max_length: int = 255, min_length: int = 0, 
                       allow_none: bool = False, field_name: str = "field") -> str:
        """Validate and sanitize string input"""
        if value is None:
            if allow_none:
                return None
            raise SecurityViolation(f"{field_name} cannot be empty", "INVALID_INPUT")
        
        if not isinstance(value, str):
            value = str(value)
        
        # Remove null bytes and control characters
        value = value.replace('\x00', '').strip()
        
        if len(value) < min_length:
            raise SecurityViolation(f"{field_name} must be at least {min_length} characters", "INVALID_INPUT")
        
        if len(value) > max_length:
            raise SecurityViolation(f"{field_name} exceeds maximum length of {max_length}", "INVALID_INPUT")
        
        return value
    
    @staticmethod
    def validate_integer(value: Any, min_value: int = None, max_value: int = None, 
                        field_name: str = "field") -> int:
        """Validate integer input"""
        try:
            value = int(value)
        except (ValueError, TypeError):
            raise SecurityViolation(f"{field_name} must be a valid integer", "INVALID_INPUT")
        
        if min_value is not None and value < min_value:
            raise SecurityViolation(f"{field_name} must be at least {min_value}", "INVALID_INPUT")
        
        if max_value is not None and value > max_value:
            raise SecurityViolation(f"{field_name} cannot exceed {max_value}", "INVALID_INPUT")
        
        return value
    
    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email format"""
        email = InputValidator.validate_string(email, max_length=255, field_name="email")
        
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        if not email_pattern.match(email):
            raise SecurityViolation("Invalid email format", "INVALID_INPUT")
        
        return email.lower()
    
    @staticmethod
    def validate_username(username: str) -> str:
        """Validate username format"""
        username = InputValidator.validate_string(
            username, 
            max_length=SECURITY_CONFIG['MAX_USERNAME_LENGTH'],
            min_length=3,
            field_name="username"
        )
        
        # Allow only alphanumeric characters, underscores, and hyphens
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            raise SecurityViolation("Username can only contain letters, numbers, underscores, and hyphens", "INVALID_INPUT")
        
        return username
    
    @staticmethod
    def sanitize_html(content: str, allowed_tags: List[str] = None) -> str:
        """Sanitize HTML content to prevent XSS"""
        if not content:
            return content
        
        # Simple HTML sanitization - escape all HTML by default
        # In production, use bleach library for more sophisticated sanitization
        return str(escape(content))
    
    @staticmethod
    def validate_file_upload(file, max_size: int = None) -> Dict[str, Any]:
        """Validate file upload security"""
        if max_size is None:
            max_size = SECURITY_CONFIG['MAX_FILE_SIZE']
        
        if not file or not file.filename:
            raise SecurityViolation("No file provided", "INVALID_FILE")
        
        # Validate filename
        filename = InputValidator.validate_string(file.filename, max_length=255, field_name="filename")
        
        # Check for directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            raise SecurityViolation("Invalid filename - directory traversal detected", "DIRECTORY_TRAVERSAL")
        
        # Validate file extension
        if '.' not in filename:
            raise SecurityViolation("File must have an extension", "INVALID_FILE")
        
        extension = filename.rsplit('.', 1)[1].lower()
        
        if extension in SECURITY_CONFIG['BLOCKED_EXTENSIONS']:
            raise SecurityViolation(f"File type .{extension} is not allowed", "BLOCKED_FILE_TYPE")
        
        if extension not in SECURITY_CONFIG['ALLOWED_EXTENSIONS']:
            raise SecurityViolation(f"File type .{extension} is not supported", "UNSUPPORTED_FILE_TYPE")
        
        # Check file size (if we can get it)
        file.seek(0, 2)  # Seek to end
        size = file.tell()
        file.seek(0)     # Reset to beginning
        
        if size > max_size:
            raise SecurityViolation(f"File size exceeds limit ({max_size} bytes)", "FILE_TOO_LARGE")
        
        return {
            'filename': filename,
            'extension': extension,
            'size': size
        }

class CSRFProtection:
    """CSRF token generation and validation"""
    
    @staticmethod
    def generate_token() -> str:
        """Generate a secure CSRF token"""
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
        session['csrf_token_time'] = time.time()
        return token
    
    @staticmethod
    def validate_token(token: str) -> bool:
        """Validate CSRF token"""
        if not token:
            return False
        
        stored_token = session.get('csrf_token')
        token_time = session.get('csrf_token_time', 0)
        
        if not stored_token:
            return False
        
        # Check if token has expired
        if time.time() - token_time > SECURITY_CONFIG['CSRF_TOKEN_EXPIRY']:
            return False
        
        # Use constant-time comparison
        return hmac.compare_digest(stored_token, token)
    
    @staticmethod
    def require_csrf_token(f):
        """Decorator to require valid CSRF token for state-changing operations"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Skip CSRF validation during development (when DEBUG is True)
            if hasattr(current_app, 'debug') and current_app.debug:
                return f(*args, **kwargs)
                
            if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
                
                if not CSRFProtection.validate_token(token):
                    security_logger.warning(f"CSRF token validation failed for {request.endpoint}")
                    raise SecurityViolation("Invalid or missing CSRF token", "CSRF_VIOLATION", "HIGH")
            
            return f(*args, **kwargs)
        return decorated_function

class RateLimiter:
    """Rate limiting implementation"""
    
    @staticmethod
    def get_client_id() -> str:
        """Get unique client identifier"""
        # Use IP address and user agent for identification
        ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
        user_agent = request.headers.get('User-Agent', '')
        return hashlib.sha256(f"{ip}:{user_agent}".encode()).hexdigest()
    
    @staticmethod
    def check_rate_limit(limit_per_minute: int = None, limit_per_hour: int = None) -> bool:
        """Check if client exceeds rate limits"""
        if limit_per_minute is None:
            limit_per_minute = SECURITY_CONFIG['RATE_LIMIT_PER_MINUTE']
        if limit_per_hour is None:
            limit_per_hour = SECURITY_CONFIG['RATE_LIMIT_PER_HOUR']
        
        client_id = RateLimiter.get_client_id()
        now = time.time()
        
        if client_id not in rate_limit_store:
            rate_limit_store[client_id] = {'requests': [], 'blocked_until': 0}
        
        client_data = rate_limit_store[client_id]
        
        # Check if client is currently blocked
        if now < client_data['blocked_until']:
            return False
        
        # Clean old requests (older than 1 hour)
        client_data['requests'] = [req_time for req_time in client_data['requests'] if now - req_time < 3600]
        
        # Check limits
        recent_requests = [req_time for req_time in client_data['requests'] if now - req_time < 60]
        
        if len(recent_requests) >= limit_per_minute:
            # Block for 1 minute
            client_data['blocked_until'] = now + 60
            security_logger.warning(f"Rate limit exceeded (per minute) for client {client_id}")
            return False
        
        if len(client_data['requests']) >= limit_per_hour:
            # Block for 1 hour
            client_data['blocked_until'] = now + 3600
            security_logger.warning(f"Rate limit exceeded (per hour) for client {client_id}")
            return False
        
        # Add current request
        client_data['requests'].append(now)
        return True
    
    @staticmethod
    def rate_limit(limit_per_minute: int = None, limit_per_hour: int = None):
        """Decorator for rate limiting"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Skip rate limiting during development (when DEBUG is True)
                if hasattr(current_app, 'debug') and current_app.debug:
                    return f(*args, **kwargs)
                    
                if not RateLimiter.check_rate_limit(limit_per_minute, limit_per_hour):
                    raise TooManyRequests("Rate limit exceeded. Please try again later.")
                return f(*args, **kwargs)
            return decorated_function
        return decorator

class SQLSecurityUtils:
    """SQL injection prevention utilities"""
    
    @staticmethod
    def validate_sql_params(params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate parameters before SQL execution"""
        validated_params = {}
        
        for key, value in params.items():
            # Validate parameter name
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', key):
                raise SecurityViolation(f"Invalid parameter name: {key}", "SQL_INJECTION_ATTEMPT")
            
            # Basic value validation
            if isinstance(value, str):
                # Check for obvious SQL injection patterns
                dangerous_patterns = [
                    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
                    r"(--|#|/\*|\*/)",
                    r"(\b(UNION|OR|AND)\s+\d+\s*=\s*\d+)",
                    r"(\'\s*OR\s*\'\d+\'\s*=\s*\'\d+)",
                ]
                
                for pattern in dangerous_patterns:
                    if re.search(pattern, value, re.IGNORECASE):
                        security_logger.error(f"SQL injection attempt detected: {pattern} in {key}")
                        raise SecurityViolation("Potentially malicious input detected", "SQL_INJECTION_ATTEMPT", "CRITICAL")
            
            validated_params[key] = value
        
        return validated_params
    
    @staticmethod
    def safe_execute_query(query: str, params: Dict[str, Any] = None):
        """Execute SQL query with security validation"""
        if params:
            params = SQLSecurityUtils.validate_sql_params(params)
        
        # Log query execution for security monitoring
        security_logger.info(f"Executing query: {query[:100]}...")
        
        return text(query), params

class SessionSecurity:
    """Session security utilities"""
    
    @staticmethod
    def validate_session() -> bool:
        """Validate current session security"""
        if 'user_id' not in session and 'username' not in session:
            return False
        
        # Check session timeout
        last_activity = session.get('last_activity', 0)
        if time.time() - last_activity > SECURITY_CONFIG['SESSION_TIMEOUT']:
            session.clear()
            return False
        
        # Update last activity
        session['last_activity'] = time.time()
        
        # Validate session integrity
        expected_signature = SessionSecurity.generate_session_signature()
        stored_signature = session.get('session_signature')
        
        if not stored_signature or not hmac.compare_digest(expected_signature, stored_signature):
            security_logger.warning("Session integrity check failed")
            session.clear()
            return False
        
        return True
    
    @staticmethod
    def generate_session_signature() -> str:
        """Generate session integrity signature"""
        user_id = session.get('user_id', '')
        username = session.get('username', '')
        ip_address = request.environ.get('REMOTE_ADDR', '')
        
        # Create signature from session data
        data = f"{user_id}:{username}:{ip_address}"
        signature = hmac.new(
            current_app.secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    @staticmethod
    def secure_session_init():
        """Initialize secure session"""
        session['session_signature'] = SessionSecurity.generate_session_signature()
        session['last_activity'] = time.time()
        session['created_at'] = time.time()
    
    @staticmethod
    def require_valid_session(f):
        """Decorator to require valid session"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not SessionSecurity.validate_session():
                raise SecurityViolation("Invalid or expired session", "SESSION_INVALID")
            return f(*args, **kwargs)
        return decorated_function

class AccessControl:
    """Enhanced access control utilities"""
    
    @staticmethod
    def validate_resource_access(user_id: str, resource_type: str, resource_id: int, 
                                action: str = "read") -> bool:
        """Validate user access to specific resources"""
        from models import db, Message, ChatRoom, UserPoints
        
        if resource_type == "chat_room":
            room = ChatRoom.query.get(resource_id)
            if not room or not room.is_active:
                return False
            # Additional room-specific access checks can be added here
            return True
        
        elif resource_type == "message":
            message = Message.query.get(resource_id)
            if not message:
                return False
            # Users can only access messages in rooms they've participated in
            user_messages = Message.query.filter_by(
                user_id=user_id, 
                room_id=message.room_id
            ).count()
            return user_messages > 0
        
        elif resource_type == "user_points":
            if action in ["read", "update"]:
                # Users can only access their own points
                return str(resource_id) == str(user_id)
        
        return False
    
    @staticmethod
    def require_resource_access(resource_type: str, resource_id_param: str = "id", 
                               action: str = "read"):
        """Decorator to require resource access validation"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                user_id = session.get('user_id')
                if not user_id:
                    raise SecurityViolation("Authentication required", "UNAUTHORIZED")
                
                # Get resource ID from request
                resource_id = kwargs.get(resource_id_param) or request.json.get(resource_id_param)
                if not resource_id:
                    raise SecurityViolation("Resource ID required", "INVALID_REQUEST")
                
                if not AccessControl.validate_resource_access(
                    user_id, resource_type, resource_id, action
                ):
                    security_logger.warning(
                        f"Unauthorized access attempt: user {user_id} -> {resource_type}:{resource_id}"
                    )
                    raise SecurityViolation("Access denied", "UNAUTHORIZED", "HIGH")
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator

class SecurityHeaders:
    """Security headers management"""
    
    @staticmethod
    def add_security_headers(response):
        """Add security headers to response"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "font-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        
        return response

class LoginSecurity:
    """Login security and brute force protection"""
    
    @staticmethod
    def check_login_attempts(ip_address: str) -> bool:
        """Check if IP has exceeded login attempts"""
        if ip_address not in login_attempts:
            return True
        
        attempts_data = login_attempts[ip_address]
        
        # Check if lockout period has expired
        if time.time() - attempts_data['last_attempt'] > SECURITY_CONFIG['LOGIN_LOCKOUT_TIME']:
            del login_attempts[ip_address]
            return True
        
        return attempts_data['count'] < SECURITY_CONFIG['MAX_LOGIN_ATTEMPTS']
    
    @staticmethod
    def record_failed_login(ip_address: str):
        """Record failed login attempt"""
        if ip_address not in login_attempts:
            login_attempts[ip_address] = {'count': 0, 'last_attempt': 0}
        
        login_attempts[ip_address]['count'] += 1
        login_attempts[ip_address]['last_attempt'] = time.time()
        
        security_logger.warning(f"Failed login attempt from {ip_address}")
    
    @staticmethod
    def record_successful_login(ip_address: str):
        """Record successful login (clear failed attempts)"""
        if ip_address in login_attempts:
            del login_attempts[ip_address]

class SecurityMiddleware:
    """Main security middleware with all protections"""
    
    @staticmethod
    def init_app(app):
        """Initialize security middleware with Flask app"""
        
        @app.before_request
        def security_before_request():
            # Skip security checks for static files
            if request.endpoint and request.endpoint.startswith('static'):
                return
            
            # Check request size
            if request.content_length and request.content_length > SECURITY_CONFIG['MAX_REQUEST_SIZE']:
                raise BadRequest("Request too large")
            
            # Rate limiting for all requests
            if not RateLimiter.check_rate_limit():
                raise TooManyRequests("Rate limit exceeded")
            
            # Validate session for protected endpoints
            if request.endpoint and not request.endpoint.startswith(('login', 'static')):
                if 'username' in session and not SessionSecurity.validate_session():
                    session.clear()
        
        @app.after_request
        def security_after_request(response):
            # Add security headers
            return SecurityHeaders.add_security_headers(response)
        
        @app.errorhandler(SecurityViolation)
        def handle_security_violation(e):
            security_logger.error(f"Security violation: {e.violation_type} - {e.message}")
            return jsonify({
                'error': 'Security violation detected',
                'message': 'Your request has been blocked for security reasons.'
            }), 400
        
    @staticmethod
    def secure_endpoint(require_auth: bool = True, require_admin: bool = False,
                       require_csrf: bool = True, rate_limit_per_minute: int = None):
        """Comprehensive endpoint security decorator"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                try:
                    # Rate limiting
                    if rate_limit_per_minute:
                        if not RateLimiter.check_rate_limit(limit_per_minute=rate_limit_per_minute):
                            raise TooManyRequests("Rate limit exceeded")
                    
                    # CSRF protection for state-changing operations
                    if require_csrf and request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                        token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
                        if not CSRFProtection.validate_token(token):
                            raise SecurityViolation("CSRF token validation failed", "CSRF_VIOLATION", "HIGH")
                    
                    # Authentication check
                    if require_auth:
                        if not SessionSecurity.validate_session():
                            raise SecurityViolation("Authentication required", "UNAUTHORIZED")
                    
                    # Admin check
                    if require_admin:
                        if not session.get('is_admin', False):
                            raise SecurityViolation("Admin access required", "UNAUTHORIZED", "HIGH")
                    
                    return f(*args, **kwargs)
                
                except SecurityViolation as e:
                    security_logger.error(f"Security violation in {request.endpoint}: {e.message}")
                    return jsonify({
                        'error': 'Security violation',
                        'message': 'Request blocked for security reasons'
                    }), 403
                
                except Exception as e:
                    security_logger.error(f"Unexpected error in {request.endpoint}: {str(e)}")
                    return jsonify({
                        'error': 'Internal error',
                        'message': 'An unexpected error occurred'
                    }), 500
            
            return decorated_function
        return decorator

# Helper functions for existing code integration
def validate_and_sanitize_input(data: Dict[str, Any], schema: Dict[str, Dict]) -> Dict[str, Any]:
    """
    Validate and sanitize input data according to schema
    
    Schema format:
    {
        'field_name': {
            'type': 'string|integer|email|username',
            'max_length': int,
            'min_length': int,
            'required': bool,
            'sanitize_html': bool
        }
    }
    """
    validated_data = {}
    
    for field_name, field_config in schema.items():
        value = data.get(field_name)
        field_type = field_config.get('type', 'string')
        required = field_config.get('required', False)
        
        if value is None or value == '':
            if required:
                raise SecurityViolation(f"{field_name} is required", "INVALID_INPUT")
            continue
        
        try:
            if field_type == 'string':
                value = InputValidator.validate_string(
                    value,
                    max_length=field_config.get('max_length', 255),
                    min_length=field_config.get('min_length', 0),
                    field_name=field_name
                )
                if field_config.get('sanitize_html', False):
                    value = InputValidator.sanitize_html(value)
            
            elif field_type == 'integer':
                value = InputValidator.validate_integer(
                    value,
                    min_value=field_config.get('min_value'),
                    max_value=field_config.get('max_value'),
                    field_name=field_name
                )
            
            elif field_type == 'email':
                value = InputValidator.validate_email(value)
            
            elif field_type == 'username':
                value = InputValidator.validate_username(value)
            
            validated_data[field_name] = value
            
        except SecurityViolation:
            raise
        except Exception as e:
            raise SecurityViolation(f"Validation error for {field_name}: {str(e)}", "VALIDATION_ERROR")
    
    return validated_data

def log_security_event(event_type: str, description: str, severity: str = "INFO", 
                      user_id: str = None, ip_address: str = None):
    """Log security events for monitoring"""
    if not ip_address:
        ip_address = request.environ.get('REMOTE_ADDR', 'unknown')
    
    if not user_id:
        user_id = session.get('user_id', 'anonymous')
    
    security_logger.log(
        getattr(logging, severity.upper(), logging.INFO),
        f"[{event_type}] {description} - User: {user_id}, IP: {ip_address}"
    )

# Export main security components
__all__ = [
    'SecurityMiddleware',
    'InputValidator', 
    'CSRFProtection',
    'RateLimiter',
    'SQLSecurityUtils',
    'SessionSecurity',
    'AccessControl',
    'SecurityHeaders',
    'LoginSecurity',
    'SecurityViolation',
    'validate_and_sanitize_input',
    'log_security_event',
    'SECURITY_CONFIG'
]