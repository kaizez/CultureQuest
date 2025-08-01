from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime, timedelta
import pymysql
import uuid
import os
import json
from login import login_bp, google_bp

# Load environment variables from the .env file
load_dotenv()

# Initialize the Flask app
app = Flask(__name__, template_folder='public')
app.secret_key = 'your_secret_key'

# Register blueprints
app.register_blueprint(login_bp)
app.register_blueprint(google_bp, url_prefix='/auth')

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'port': int(os.getenv('DB_PORT')),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

def get_db_connection():
    """Get database connection"""
    try:
        return pymysql.connect(**DB_CONFIG)
    except Exception as e:
        print(f"Database connection failed: {e}")
        return None

def init_database():
    """Initialize database tables"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        with connection.cursor() as cursor:
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id VARCHAR(36) PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    password VARCHAR(255),
                    profile_picture TEXT,
                    occupation VARCHAR(100),
                    birthday DATE,
                    labels TEXT,
                    online_start_time VARCHAR(10),
                    online_end_time VARCHAR(10),
                    is_google_user BOOLEAN DEFAULT FALSE,
                    email_verified BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_login DATETIME,
                    INDEX idx_username (username),
                    INDEX idx_email (email)
                )
            """)
            
            # Create verification_codes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS verification_codes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(120) NOT NULL,
                    code VARCHAR(6) NOT NULL,
                    expires DATETIME NOT NULL,
                    attempts INT DEFAULT 0,
                    user_data TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_email (email)
                )
            """)
            
            # Create reset_codes table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reset_codes (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(120) NOT NULL,
                    code VARCHAR(6) NOT NULL,
                    expires DATETIME NOT NULL,
                    attempts INT DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_email (email)
                )
            """)
            
        connection.commit()
        print("Database tables created successfully!")
        return True
    except Exception as e:
        print(f"Error creating database tables: {e}")
        return False
    finally:
        connection.close()

# User operations
def find_user_by_username(username):
    """Find user by username"""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            return cursor.fetchone()
    except Exception as e:
        print(f"Error finding user by username: {e}")
        return None
    finally:
        connection.close()

def find_user_by_email(email):
    """Find user by email"""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            return cursor.fetchone()
    except Exception as e:
        print(f"Error finding user by email: {e}")
        return None
    finally:
        connection.close()

def create_user(username, email, password, is_google_user=False, profile_picture=None, email_verified=False):
    """Create a new user"""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        with connection.cursor() as cursor:
            user_id = str(uuid.uuid4())
            hashed_password = generate_password_hash(password) if password else None
            
            cursor.execute("""
                INSERT INTO users (id, username, email, password, profile_picture, 
                                 is_google_user, email_verified, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, username, email, hashed_password, profile_picture,
                  is_google_user, email_verified, datetime.utcnow()))
            
            connection.commit()
            return {
                'id': user_id,
                'username': username,
                'email': email,
                'password': hashed_password,
                'profile_picture': profile_picture,
                'is_google_user': is_google_user,
                'email_verified': email_verified
            }
    except Exception as e:
        print(f"Error creating user: {e}")
        return None
    finally:
        connection.close()

def update_user_login_time(username):
    """Update user's last login time"""
    connection = get_db_connection()
    if not connection:
        return
    
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE users SET last_login = %s WHERE username = %s",
                (datetime.utcnow(), username)
            )
            connection.commit()
    except Exception as e:
        print(f"Error updating login time: {e}")
    finally:
        connection.close()

# Routes
@app.route('/')
def landing_page():
    return render_template('landing.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Username and password are required!", "danger")
        return redirect(url_for('login_page'))

    # Check for admin login
    if username == 'admin' and password == 'password':
        session['username'] = username
        session['is_admin'] = True
        flash("Welcome, Admin!", "success")
        return redirect(url_for('admin_dashboard'))

    # Check regular user login
    user = find_user_by_username(username)

    if user and user.get('password') and check_password_hash(user['password'], password):
        # Clear any existing flash messages to prevent overlapping  
        if '_flashes' in session:
            session.pop('_flashes', None)
        
        # Update last login time
        update_user_login_time(username)
        
        session['username'] = username
        session['email'] = user['email']
        session['profile_picture'] = user.get('profile_picture')
        session['user_id'] = user['id']
        session['is_admin'] = False
        
        flash(f"Welcome back, {username}!", "success")
        return redirect(url_for('profile'))
    else:
        flash("Invalid credentials!", "danger")
        return redirect(url_for('login_page'))

@app.route('/profile')
def profile():
    """User profile page"""
    if 'username' in session and not session.get('is_admin', False):
        username = session['username']
        user = find_user_by_username(username)
        if user:
            return render_template('profile.html', 
                                 username=username, 
                                 email=user['email'],
                                 profile_picture=user.get('profile_picture'), 
                                 occupation=user.get('occupation'), 
                                 birthday=user.get('birthday'), 
                                 labels=user.get('labels'),
                                 online_start_time=user.get('online_start_time'), 
                                 online_end_time=user.get('online_end_time'))
    return redirect(url_for('login_page'))

@app.route('/signup')
def signup_page():
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login_page'))

# Admin routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('login_page'))
    
    # Get user count
    connection = get_db_connection()
    total_users = 0
    if connection:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) as count FROM users")
                result = cursor.fetchone()
                total_users = result['count'] if result else 0
        except:
            pass
        finally:
            connection.close()
    
    return render_template('admin_dashboard.html', 
                         total_users=total_users,
                         google_users=0,
                         regular_users=total_users,
                         users_today=0,
                         users_this_week=0,
                         recent_users=[],
                         all_users=[])

@app.route('/admin/export-users')
def admin_export_users():
    if not session.get('is_admin'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('login_page'))
    
    # For now, redirect back to dashboard
    flash('Export feature coming soon!', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user/<int:user_id>')
def admin_user_detail(user_id):
    if not session.get('is_admin'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('login_page'))
    
    # For now, redirect back to dashboard
    flash('User details feature coming soon!', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('is_admin'):
        flash('Admin access required.', 'danger')
        return redirect(url_for('login_page'))
    
    # For now, redirect back to dashboard
    flash('Delete user feature coming soon!', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/forgot-password')
def forgot_password_page():
    return render_template('forget.html')

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form.get('email')
    flash('Password reset functionality coming soon!', 'info')
    return redirect(url_for('forgot_password_page'))

@app.route('/verify-code')
def verify_code_page():
    return render_template('verify_code.html')

@app.route('/verify-code', methods=['POST'])
def verify_reset_code():
    code = request.form.get('code')
    flash('Code verification functionality coming soon!', 'info')
    return redirect(url_for('verify_code_page'))

@app.route('/reset-password')
def reset_password_page():
    return render_template('reset_password.html')

@app.route('/reset-password', methods=['POST'])
def reset_password():
    password = request.form.get('password')
    flash('Password reset functionality coming soon!', 'info')
    return redirect(url_for('login_page'))

@app.route('/resend-code', methods=['POST'])
def resend_reset_code():
    return {"success": True, "message": "Code resent successfully!"}

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    
    if not username or not email or not password:
        flash('All fields are required.', 'danger')
        return redirect(url_for('signup_page'))
    
    connection = get_db_connection()
    if not connection:
        flash('Database connection failed.', 'danger')
        return redirect(url_for('signup_page'))
    
    try:
        with connection.cursor() as cursor:
            # Check if user already exists
            cursor.execute("SELECT id FROM users WHERE email = %s OR username = %s", (email, username))
            if cursor.fetchone():
                flash('User with this email or username already exists.', 'danger')
                return redirect(url_for('signup_page'))
            
            # Create new user with hashed password
            from datetime import datetime
            from werkzeug.security import generate_password_hash
            hashed_password = generate_password_hash(password)
            cursor.execute("""
                INSERT INTO users (username, email, password, created_at) 
                VALUES (%s, %s, %s, %s)
            """, (username, email, hashed_password, datetime.now()))
            
        connection.commit()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login_page'))
        
    except Exception as e:
        flash(f'Error creating account: {str(e)}', 'danger')
        return redirect(url_for('signup_page'))
    finally:
        connection.close()

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return {"success": False, "message": "Not logged in"}, 401
    
    # For now, just return success
    return {"success": True, "message": "Profile updated successfully!"}

@app.route('/auth/google')
def google_login():
    flash('Google login is currently disabled. Please use email/password login or contact administrator.', 'info')
    return redirect(url_for('login_page'))

@app.route('/auth/google/callback')
def google_callback():
    flash('Google login callback - functionality not configured.', 'info')
    return redirect(url_for('login_page'))

if __name__ == '__main__':
    print("Starting CultureQuest with MySQL...")
    print(f"Database: mysql://{DB_CONFIG['user']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}")
    
    # Initialize database
    if init_database():
        print("Database ready!")
        print("Application starting at: http://127.0.0.1:5000")
        app.run(debug=True)
    else:
        print("Database initialization failed!")
        print("Please check your database connection and try again.")