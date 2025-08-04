from flask import session, redirect, request, jsonify, flash, url_for
from functools import wraps
from security_logger import log_authorization_failure

def login_required(f):
    """Login required decorator - Protects against unauthorized access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"[AUTH DEBUG] Checking login for route: {request.endpoint}")
        print(f"[AUTH DEBUG] Session keys: {list(session.keys())}")
        print(f"[AUTH DEBUG] Username in session: {'username' in session}")
        print(f"[AUTH DEBUG] User ID in session: {'user_id' in session}")
        
        # Check if user is logged in via session
        # For admin users, allow access if they have username and is_admin, even without user_id
        is_admin_session = session.get('is_admin', False) and 'username' in session
        
        if 'username' not in session or ('user_id' not in session and not is_admin_session):
            print(f"[AUTH DEBUG] User not logged in, redirecting to login")
            # For AJAX requests, return JSON error
            if request.is_json or request.headers.get('Content-Type') == 'application/json':
                return jsonify({'error': 'Authentication required', 'redirect': url_for('login.login_page')}), 401
            
            # For regular requests, redirect to login
            flash('Please log in to access this page.', 'warning')
            return redirect('/login')
        
        print(f"[AUTH DEBUG] Login access granted for {session.get('username')}")
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Admin required decorator - Protects against unauthorized access to admin functions"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"[AUTH DEBUG] Checking admin access for route: {request.endpoint}")
        print(f"[AUTH DEBUG] Session keys: {list(session.keys())}")
        print(f"[AUTH DEBUG] Username in session: {'username' in session}")
        print(f"[AUTH DEBUG] User ID in session: {'user_id' in session}")
        print(f"[AUTH DEBUG] Is admin: {session.get('is_admin', False)}")
        
        # Check if user is logged in
        # For admin users, allow access if they have username and is_admin, even without user_id
        is_admin_session = session.get('is_admin', False) and 'username' in session
        
        if 'username' not in session or ('user_id' not in session and not is_admin_session):
            print(f"[AUTH DEBUG] User not logged in, redirecting to login")
            if request.is_json or request.headers.get('Content-Type') == 'application/json':
                return jsonify({'error': 'Authentication required', 'redirect': url_for('login.login_page')}), 401
            
            flash('Please log in to access this page.', 'warning')
            return redirect('/login')
        
        # Check if user is admin
        if not session.get('is_admin', False):
            print(f"[AUTH DEBUG] User logged in but not admin, access denied")
            log_authorization_failure(['admin'], session.get('role', 'user'))  # Log unauthorized access attempt
            if request.is_json or request.headers.get('Content-Type') == 'application/json':
                return jsonify({'error': 'Admin access required'}), 403
            
            flash('Admin access required.', 'error')
            return "Access Denied: Admin privileges required", 403  # Protects against unauthorized admin access
        
        print(f"[AUTH DEBUG] Admin access granted for {session.get('username')}")
        return f(*args, **kwargs)
    return decorated_function