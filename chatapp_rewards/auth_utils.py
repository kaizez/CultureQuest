from functools import wraps
from flask import session, redirect, url_for, request, jsonify, flash
import sys
import os

def require_login(f):
    """Decorator to require user login for routes"""
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
            return redirect(url_for('login.login_page'))
        
        print(f"[AUTH DEBUG] Login access granted for {session.get('username')}")
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Decorator to require admin access for routes"""
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
            return redirect(url_for('login.login_page'))
        
        # Check if user is admin
        if not session.get('is_admin', False):
            print(f"[AUTH DEBUG] User logged in but not admin, redirecting to profile")
            if request.is_json or request.headers.get('Content-Type') == 'application/json':
                return jsonify({'error': 'Admin access required'}), 403
            
            flash('Admin access required.', 'error')
            return redirect(url_for('login.profile'))
        
        print(f"[AUTH DEBUG] Admin access granted for {session.get('username')}")
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current logged in user information from session"""
    if 'username' not in session:
        return None
    
    # Get profile picture URL
    user_id = session.get('user_id')
    profile_picture_url = None
    
    if user_id:
        # Check if user has a database-stored profile picture
        profile_picture = session.get('profile_picture')
        if profile_picture and profile_picture.startswith('db_image_'):
            profile_picture_url = f'/profile-picture/{user_id}'
        elif profile_picture:
            profile_picture_url = f'/static/{profile_picture}'
        else:
            profile_picture_url = '/static/default_profile.png'
    else:
        profile_picture_url = '/static/default_profile.png'
    
    return {
        'username': session['username'],
        'user_id': session.get('user_id'),
        'email': session.get('email'),
        'is_admin': session.get('is_admin', False),
        'profile_picture_url': profile_picture_url
    }

def get_user_id():
    """Get current user ID from session"""
    return session.get('user_id')

def get_username():
    """Get current username from session"""
    return session.get('username')

def get_navbar_template():
    """Get the appropriate navbar template based on user login status and role"""
    if 'username' not in session:
        # Not logged in - use login navbar with sign in/up
        return 'includes/_login_navbar.html'
    elif session.get('is_admin', False):
        # Admin user - use admin navbar
        return 'includes/_adminnavbar.html'
    else:
        # Regular logged-in user - use user navbar
        return 'includes/_usernavbar.html'