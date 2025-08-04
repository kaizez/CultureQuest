from flask import session, redirect, request
from functools import wraps
from security_logger import log_authorization_failure

def login_required(f):
    """Login required decorator - Protects against unauthorized access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in - Protects against unauthorized access
        if 'username' not in session or 'email' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Admin required decorator - Protects against unauthorized access to admin functions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'username' not in session or 'email' not in session:
            return redirect('/login')
        
        # Check if user has admin role - Protects against privilege escalation attacks
        user_role = session.get('role', 'user')  # Default to 'user' if no role specified
        if user_role not in ['admin', 'super_admin', 'moderator']:
            log_authorization_failure(['admin', 'super_admin', 'moderator'], user_role)  # Log unauthorized access attempt
            return "Access Denied: Admin privileges required", 403  # Protects against unauthorized admin access
        
        return f(*args, **kwargs)
    return decorated_function