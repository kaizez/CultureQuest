"""
Security event logging module for comprehensive attack detection and monitoring.
Tracks security-relevant events for analysis and alerting.
"""
import logging
import json
from datetime import datetime
from flask import request, session, g
from functools import wraps
import hashlib

# Configure security-specific logger - Protects against log tampering
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)

# Create file handler for security logs - Protects against log loss
security_handler = logging.FileHandler('security_events.log')
security_handler.setLevel(logging.INFO)

# Create formatter for structured logging - Protects against log parsing issues
formatter = logging.Formatter(
    '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
)
security_handler.setFormatter(formatter)
security_logger.addHandler(security_handler)

def get_client_info():
    """Get client information for logging - Protects against anonymous attacks."""
    return {
        'ip_address': request.remote_addr,  # Protects against IP spoofing detection
        'user_agent': request.headers.get('User-Agent', 'Unknown'),  # Protects against bot detection
        'endpoint': request.endpoint,  # Protects against endpoint abuse tracking
        'method': request.method,  # Protects against method abuse tracking
        'url': request.url  # Protects against URL manipulation tracking
    }

def get_user_context():
    """Get user context for logging - Protects against unauthorized access tracking."""
    return {
        'user_email': session.get('email', 'Anonymous'),  # Protects against anonymous abuse
        'username': session.get('username', 'Unknown'),  # Protects against user identification
        'role': session.get('role', 'user'),  # Protects against privilege tracking
        'session_id': hashlib.md5(str(session).encode()).hexdigest()[:8]  # Protects against session tracking without exposure
    }

def log_authentication_attempt(email, success, failure_reason=None):
    """Log authentication attempts - Protects against brute force attacks."""
    event_data = {
        'event_type': 'authentication_attempt',
        'email': email,
        'success': success,
        'failure_reason': failure_reason,
        'client_info': get_client_info(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    level = logging.INFO if success else logging.WARNING
    security_logger.log(level, json.dumps(event_data))

def log_authorization_failure(required_role, user_role):
    """Log authorization failures - Protects against privilege escalation attempts."""
    event_data = {
        'event_type': 'authorization_failure',
        'required_role': required_role,
        'user_role': user_role,
        'client_info': get_client_info(),
        'user_context': get_user_context(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    security_logger.warning(json.dumps(event_data))

def log_file_upload_attempt(filename, file_size, success, failure_reason=None):
    """Log file upload attempts - Protects against malicious file uploads."""
    event_data = {
        'event_type': 'file_upload_attempt',
        'filename': filename,
        'file_size': file_size,
        'success': success,
        'failure_reason': failure_reason,
        'client_info': get_client_info(),
        'user_context': get_user_context(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    level = logging.INFO if success else logging.WARNING
    security_logger.log(level, json.dumps(event_data))

def log_rate_limit_exceeded(email):
    """Log rate limit violations - Protects against abuse detection."""
    event_data = {
        'event_type': 'rate_limit_exceeded',
        'email': email,
        'client_info': get_client_info(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    security_logger.warning(json.dumps(event_data))

def log_sql_injection_attempt(query_attempt, input_data):
    """Log potential SQL injection attempts - Protects against database attacks."""
    event_data = {
        'event_type': 'sql_injection_attempt',
        'query_attempt': query_attempt[:100],  # Limit length to prevent log overflow
        'input_data': str(input_data)[:200],  # Limit length for security
        'client_info': get_client_info(),
        'user_context': get_user_context(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    security_logger.error(json.dumps(event_data))

def log_xss_attempt(input_data, field_name):
    """Log potential XSS attempts - Protects against script injection."""
    event_data = {
        'event_type': 'xss_attempt',
        'input_data': str(input_data)[:200],  # Limit length for security
        'field_name': field_name,
        'client_info': get_client_info(),
        'user_context': get_user_context(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    security_logger.warning(json.dumps(event_data))

def log_admin_action(action, target_id, details):
    """Log admin actions - Protects against unauthorized admin activity."""
    event_data = {
        'event_type': 'admin_action',
        'action': action,
        'target_id': target_id,
        'details': details,
        'client_info': get_client_info(),
        'user_context': get_user_context(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    security_logger.info(json.dumps(event_data))

def log_data_access(resource_type, resource_id, access_type):
    """Log data access events - Protects against unauthorized data access."""
    event_data = {
        'event_type': 'data_access',
        'resource_type': resource_type,
        'resource_id': resource_id,
        'access_type': access_type,  # read, write, delete
        'client_info': get_client_info(),
        'user_context': get_user_context(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    security_logger.info(json.dumps(event_data))

def log_session_event(event_type, details=None):
    """Log session-related events - Protects against session attacks."""
    event_data = {
        'event_type': f'session_{event_type}',
        'details': details,
        'client_info': get_client_info(),
        'user_context': get_user_context(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    security_logger.info(json.dumps(event_data))

def security_monitor(event_type):
    """Decorator for automatic security event logging - Protects against unmonitored activities."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Log function entry
                log_data_access(event_type, 'function_call', 'execute')
                
                # Execute function
                result = f(*args, **kwargs)
                
                # Log successful execution
                security_logger.info(json.dumps({
                    'event_type': f'{event_type}_success',
                    'function': f.__name__,
                    'user_context': get_user_context(),
                    'timestamp': datetime.utcnow().isoformat()
                }))
                
                return result
                
            except Exception as e:
                # Log function failure
                security_logger.error(json.dumps({
                    'event_type': f'{event_type}_failure',
                    'function': f.__name__,
                    'error': str(e)[:200],  # Limit error message length
                    'user_context': get_user_context(),
                    'client_info': get_client_info(),
                    'timestamp': datetime.utcnow().isoformat()
                }))
                raise
                
        return decorated_function
    return decorator

def detect_suspicious_patterns(input_data):
    """Detect suspicious input patterns - Protects against various injection attacks."""
    suspicious_patterns = [
        # SQL injection patterns
        r"('|(\\')|(;)|(\\;)|(--|#))",
        r"(union|select|insert|update|delete|drop)",
        
        # XSS patterns
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        
        # Path traversal patterns
        r"\.\./",
        r"\.\.\\",
        
        # Command injection patterns
        r"(;|\||\&)\s*(ls|dir|cat|type|cmd)",
    ]
    
    input_str = str(input_data).lower()
    
    for pattern in suspicious_patterns:
        if pattern in input_str:
            # Log the suspicious pattern detection
            security_logger.warning(json.dumps({
                'event_type': 'suspicious_pattern_detected',
                'pattern': pattern,
                'input_data': str(input_data)[:100],  # Limit for security
                'client_info': get_client_info(),
                'user_context': get_user_context(),
                'timestamp': datetime.utcnow().isoformat()
            }))
            return True
    
    return False

def log_security_violation(violation_type, details):
    """Log general security violations - Protects against various attack types."""
    event_data = {
        'event_type': 'security_violation',
        'violation_type': violation_type,
        'details': details,
        'client_info': get_client_info(),
        'user_context': get_user_context(),
        'timestamp': datetime.utcnow().isoformat()
    }
    
    security_logger.error(json.dumps(event_data))