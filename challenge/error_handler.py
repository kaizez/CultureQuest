"""
Secure error handling module to prevent information disclosure.
Provides safe error responses that don't leak sensitive information.
"""
import logging
from flask import jsonify, render_template
from werkzeug.exceptions import HTTPException

# Configure secure logging - Protects against log injection
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),  # Protects against log loss
        logging.StreamHandler()  # For development visibility
    ]
)

logger = logging.getLogger(__name__)

def sanitize_error_message(error_msg):
    """Sanitize error messages to prevent information disclosure - Protects against data leakage."""
    # Remove sensitive information patterns - Protects against path disclosure
    sensitive_patterns = [
        r'C:\\.*?\\',  # Windows paths
        r'/[a-zA-Z0-9_\-/]*/',  # Unix paths
        r'password',  # Password references
        r'secret',  # Secret references
        r'key',  # Key references
        r'token',  # Token references
        r'database',  # Database references
        r'connection',  # Connection strings
    ]
    
    sanitized = str(error_msg).lower()
    
    # Replace sensitive information with generic message
    for pattern in sensitive_patterns:
        if pattern in sanitized:
            return "An internal error occurred. Please contact support."
    
    return "An error occurred while processing your request."

def handle_validation_error(error_details):
    """Handle validation errors safely - Protects against validation bypass attempts."""
    logger.warning(f"Validation error: {error_details}")  # Log for monitoring - Protects against undetected attacks
    
    # Return generic validation error - Protects against information disclosure
    return {
        'error': 'Invalid input provided',
        'status': 'validation_failed'
    }, 400

def handle_authentication_error():
    """Handle authentication errors safely - Protects against user enumeration."""
    logger.warning("Authentication failed")  # Log for monitoring - Protects against brute force attacks
    
    # Generic message - Protects against user enumeration attacks
    return {
        'error': 'Authentication required',
        'status': 'unauthorized'
    }, 401

def handle_authorization_error():
    """Handle authorization errors safely - Protects against privilege escalation attempts."""
    logger.warning("Authorization failed")  # Log for monitoring - Protects against unauthorized access attempts
    
    # Generic message - Protects against information disclosure
    return {
        'error': 'Access denied',
        'status': 'forbidden'
    }, 403

def handle_file_upload_error(error_details):
    """Handle file upload errors safely - Protects against file upload attacks."""
    logger.warning(f"File upload error: {sanitize_error_message(str(error_details))}")  # Log for monitoring
    
    # Return sanitized error - Protects against path disclosure
    return {
        'error': 'File upload failed. Please check file type and size.',
        'status': 'upload_failed'
    }, 400

def handle_rate_limit_error():
    """Handle rate limiting errors - Protects against abuse detection."""
    logger.warning("Rate limit exceeded")  # Log for monitoring - Protects against sustained attacks
    
    return {
        'error': 'Too many requests. Please try again later.',
        'status': 'rate_limited'
    }, 429

def handle_database_error(error_details):
    """Handle database errors safely - Protects against database information disclosure."""
    logger.error(f"Database error: {str(error_details)}")  # Log full details for debugging
    
    # Return generic error - Protects against database schema disclosure
    return {
        'error': 'A database error occurred. Please try again.',
        'status': 'database_error'
    }, 500

def handle_generic_error(error_details):
    """Handle generic errors safely - Protects against information disclosure."""
    logger.error(f"Generic error: {str(error_details)}")  # Log full details for debugging
    
    # Return sanitized error - Protects against sensitive information leakage
    sanitized_msg = sanitize_error_message(str(error_details))
    return {
        'error': sanitized_msg,
        'status': 'internal_error'
    }, 500

def setup_error_handlers(app):
    """Setup secure error handlers for Flask app - Protects against information disclosure."""
    
    @app.errorhandler(400)
    def handle_bad_request(e):
        """Handle bad request errors - Protects against malformed request exploitation."""
        logger.warning("Bad request received")
        return render_template('error.html', 
                             error_code=400, 
                             error_message="Bad request"), 400
    
    @app.errorhandler(401)
    def handle_unauthorized(e):
        """Handle unauthorized errors - Protects against authentication bypass."""
        return handle_authentication_error()
    
    @app.errorhandler(403)
    def handle_forbidden(e):
        """Handle forbidden errors - Protects against privilege escalation."""
        return handle_authorization_error()
    
    @app.errorhandler(404)
    def handle_not_found(e):
        """Handle not found errors - Protects against path enumeration."""
        logger.info("404 error - page not found")
        return render_template('error.html', 
                             error_code=404, 
                             error_message="Page not found"), 404
    
    @app.errorhandler(429)
    def handle_too_many_requests(e):
        """Handle rate limit errors - Protects against abuse."""
        return handle_rate_limit_error()
    
    @app.errorhandler(500)
    def handle_internal_error(e):
        """Handle internal server errors - Protects against information disclosure."""
        logger.error(f"Internal server error: {str(e)}")
        return render_template('error.html', 
                             error_code=500, 
                             error_message="Internal server error"), 500
    
    @app.errorhandler(Exception)
    def handle_unexpected_error(e):
        """Handle unexpected errors - Protects against unhandled exceptions."""
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        return render_template('error.html', 
                             error_code=500, 
                             error_message="An unexpected error occurred"), 500

def log_security_event(event_type, details, user_email=None):
    """Log security events for monitoring - Protects against undetected attacks."""
    log_entry = f"SECURITY EVENT - Type: {event_type}"
    if user_email:
        log_entry += f" - User: {user_email}"
    log_entry += f" - Details: {details}"
    
    logger.warning(log_entry)  # Use warning level for security events