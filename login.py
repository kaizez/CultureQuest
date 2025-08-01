from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, UTC
from dotenv import load_dotenv
from flask_dance.contrib.google import make_google_blueprint, google
import os
import pymysql
from functools import wraps
import uuid
import random
import string
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import base64
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import Flow

# Load environment variables from .env file
load_dotenv()

# Create login blueprint
login_bp = Blueprint('login', __name__, template_folder='public')

# Admin credentials
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'password'

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'staging.nypdsf.me'),
    'port': int(os.getenv('DB_PORT', 8080)),
    'user': os.getenv('DB_USER', 'SQLUser'),
    'password': os.getenv('DB_PASSWORD', 'Pleasestopleakingenv'),
    'database': os.getenv('DB_NAME', 'culturequest'),
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}

# Google OAuth setup (will be registered in main app only if configured)
google_bp = None
if os.getenv('GOOGLE_CLIENT_ID') and os.getenv('GOOGLE_CLIENT_SECRET'):
    google_bp = make_google_blueprint(
        client_id=os.getenv('GOOGLE_CLIENT_ID'),
        client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
        scope=[
            "openid",
            "https://www.googleapis.com/auth/userinfo.email", 
            "https://www.googleapis.com/auth/userinfo.profile"
        ],
        redirect_to='login.google_callback'
    )

# Database Functions
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

def find_user_by_id(user_id):
    """Find user by ID"""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            return cursor.fetchone()
    except Exception as e:
        print(f"Error finding user by ID: {e}")
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

def update_user(user_id, updates):
    """Update user data"""
    connection = get_db_connection()
    if not connection:
        return None
    
    try:
        with connection.cursor() as cursor:
            # Build dynamic UPDATE query
            set_clause = ', '.join([f"{key} = %s" for key in updates.keys()])
            values = list(updates.values()) + [user_id]
            
            cursor.execute(f"UPDATE users SET {set_clause} WHERE id = %s", values)
            connection.commit()
            
            # Return updated user
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            return cursor.fetchone()
    except Exception as e:
        print(f"Error updating user: {e}")
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

def delete_user_by_id(user_id):
    """Delete user by ID"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            connection.commit()
            return cursor.rowcount > 0
    except Exception as e:
        print(f"Error deleting user: {e}")
        return False
    finally:
        connection.close()

def get_user_stats():
    """Get user statistics"""
    connection = get_db_connection()
    if not connection:
        return {
            'total_users': 0,
            'google_users': 0,
            'regular_users': 0,
            'users_today': 0,
            'users_this_week': 0
        }
    
    try:
        with connection.cursor() as cursor:
            # Total users
            cursor.execute("SELECT COUNT(*) as count FROM users")
            total_users = cursor.fetchone()['count']
            
            # Google users
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE is_google_user = TRUE")
            google_users = cursor.fetchone()['count']
            
            regular_users = total_users - google_users
            
            # Users today
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE DATE(created_at) = CURDATE()")
            users_today = cursor.fetchone()['count']
            
            # Users this week
            cursor.execute("SELECT COUNT(*) as count FROM users WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)")
            users_this_week = cursor.fetchone()['count']
            
            return {
                'total_users': total_users,
                'google_users': google_users,
                'regular_users': regular_users,
                'users_today': users_today,
                'users_this_week': users_this_week
            }
    except Exception as e:
        print(f"Error getting user stats: {e}")
        return {
            'total_users': 0,
            'google_users': 0,
            'regular_users': 0,
            'users_today': 0,
            'users_this_week': 0
        }
    finally:
        connection.close()

# Password Reset Functions

def generate_reset_code():
    """Generate a 6-digit reset code"""
    return ''.join(random.choices(string.digits, k=6))

def store_reset_code(email, code):
    """Store reset code with expiration time"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        with connection.cursor() as cursor:
            # Remove any existing reset code for this email
            cursor.execute("DELETE FROM reset_codes WHERE email = %s", (email,))
            
            # Insert new reset code
            expires = datetime.now(UTC) + timedelta(minutes=15)
            cursor.execute("""
                INSERT INTO reset_codes (email, code, expires, attempts) 
                VALUES (%s, %s, %s, 0)
            """, (email, code, expires))
            
            connection.commit()
            return True
    except Exception as e:
        print(f"Error storing reset code: {e}")
        return False
    finally:
        connection.close()

def verify_reset_code_helper(email, provided_code):
    """Verify reset code and check expiration"""
    print(f"DEBUG: verify_reset_code_helper called with email={email}, code={provided_code}")
    connection = get_db_connection()
    if not connection:
        print("DEBUG: Database connection failed")
        return False, "Database connection failed"
    
    try:
        with connection.cursor() as cursor:
            # Find reset code for this email
            cursor.execute("SELECT * FROM reset_codes WHERE email = %s", (email,))
            code_data = cursor.fetchone()
            print(f"DEBUG: Retrieved reset code_data: {code_data}")
            
            if not code_data:
                print("DEBUG: No reset code found")
                return False, "No reset code found for this email"
            
            print(f"DEBUG: Stored reset code={code_data['code']}, provided code={provided_code}")
            print(f"DEBUG: Reset code expires at: {code_data['expires']}, current time: {datetime.now(UTC)}")
            
            # Check if code has expired (handle timezone properly)
            current_time = datetime.now(UTC)
            expires_time = code_data['expires']
            
            # If expires_time is naive (no timezone), assume it's UTC
            if expires_time.tzinfo is None:
                expires_time = expires_time.replace(tzinfo=UTC)
            
            if current_time > expires_time:
                print("DEBUG: Reset code has expired")
                # Remove expired code
                cursor.execute("DELETE FROM reset_codes WHERE email = %s", (email,))
                connection.commit()
                return False, "Reset code has expired"
            
            # Check attempts limit
            if code_data['attempts'] >= 3:
                print("DEBUG: Too many reset attempts")
                return False, "Too many failed attempts. Please request a new code."
            
            # Check if code matches
            if code_data['code'] != provided_code:
                print("DEBUG: Reset code does not match")
                # Increment attempts
                cursor.execute(
                    "UPDATE reset_codes SET attempts = attempts + 1 WHERE email = %s",
                    (email,)
                )
                connection.commit()
                return False, "Invalid reset code"
            
            print("DEBUG: Reset code matches! Processing success...")
            # Code is valid - remove it to prevent reuse
            cursor.execute("DELETE FROM reset_codes WHERE email = %s", (email,))
            connection.commit()
            return True, "Code verified successfully"
    except Exception as e:
        print(f"ERROR: Exception in verify_reset_code_helper: {e}")
        import traceback
        traceback.print_exc()
        return False, "Error verifying code"
    finally:
        connection.close()

def cleanup_expired_codes():
    """Remove expired reset codes"""
    connection = get_db_connection()
    if not connection:
        return
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM reset_codes WHERE expires < %s", (datetime.now(UTC),))
            cursor.execute("DELETE FROM verification_codes WHERE expires < %s", (datetime.now(UTC),))
            connection.commit()
    except Exception as e:
        print(f"Error cleaning up expired codes: {e}")
    finally:
        connection.close()

# Email Verification Functions

def generate_verification_code():
    """Generate a 6-digit verification code"""
    return ''.join(random.choices(string.digits, k=6))

def store_verification_code(email, code, user_data):
    """Store verification code with expiration time and user data"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        with connection.cursor() as cursor:
            # Remove any existing verification code for this email
            cursor.execute("DELETE FROM verification_codes WHERE email = %s", (email,))
            
            # Insert new verification code with user data as JSON
            expires = datetime.now(UTC) + timedelta(minutes=15)
            import json
            cursor.execute("""
                INSERT INTO verification_codes (email, code, expires, attempts, user_data) 
                VALUES (%s, %s, %s, 0, %s)
            """, (email, code, expires, json.dumps(user_data)))
            
            connection.commit()
            return True
    except Exception as e:
        print(f"Error storing verification code: {e}")
        return False
    finally:
        connection.close()

def verify_email_code_helper(email, provided_code):
    """Verify email verification code and check expiration"""
    print(f"DEBUG: verify_email_code_helper called with email={email}, code={provided_code}")
    connection = get_db_connection()
    if not connection:
        print("DEBUG: Database connection failed")
        return False, "Database connection failed", None
    
    try:
        with connection.cursor() as cursor:
            # Find verification code for this email
            cursor.execute("SELECT * FROM verification_codes WHERE email = %s", (email,))
            code_data = cursor.fetchone()
            print(f"DEBUG: Retrieved code_data: {code_data}")
            
            if not code_data:
                print("DEBUG: No verification code found")
                return False, "No verification code found for this email", None
            
            print(f"DEBUG: Stored code={code_data['code']}, provided code={provided_code}")
            print(f"DEBUG: Code expires at: {code_data['expires']}, current time: {datetime.now(UTC)}")
            
            # Check if code has expired (handle timezone properly)
            current_time = datetime.now(UTC)
            expires_time = code_data['expires']
            
            # If expires_time is naive (no timezone), assume it's UTC
            if expires_time.tzinfo is None:
                expires_time = expires_time.replace(tzinfo=UTC)
            
            print(f"DEBUG: Current time: {current_time}, Expires time: {expires_time}")
            
            if current_time > expires_time:
                print("DEBUG: Code has expired")
                # Remove expired code
                cursor.execute("DELETE FROM verification_codes WHERE email = %s", (email,))
                connection.commit()
                return False, "Verification code has expired", None
            
            # Check attempts limit
            if code_data['attempts'] >= 3:
                print("DEBUG: Too many attempts")
                return False, "Too many failed attempts. Please request a new code.", None
            
            # Check if code matches
            if code_data['code'] != provided_code:
                print("DEBUG: Code does not match")
                # Increment attempts
                cursor.execute(
                    "UPDATE verification_codes SET attempts = attempts + 1 WHERE email = %s",
                    (email,)
                )
                connection.commit()
                return False, "Invalid verification code", None
            
            print("DEBUG: Code matches! Processing success...")
            # Code is valid - get user data and remove verification code
            import json
            user_data = json.loads(code_data['user_data']) if code_data['user_data'] else None
            print(f"DEBUG: User data retrieved: {user_data}")
            cursor.execute("DELETE FROM verification_codes WHERE email = %s", (email,))
            connection.commit()
            return True, "Email verified successfully", user_data
    except Exception as e:
        print(f"ERROR: Exception in verify_email_code_helper: {e}")
        import traceback
        traceback.print_exc()
        return False, "Error verifying code", None
    finally:
        connection.close()

def cleanup_expired_verification_codes():
    """Remove expired verification codes"""
    cleanup_expired_codes()  # This function now handles both reset and verification codes

def send_verification_email(email, code):
    """Send email verification email using Gmail API or SMTP"""
    try:
        # Clean up expired codes first
        cleanup_expired_verification_codes()
        
        # Try Gmail API first, then fallback to SMTP
        success = send_verification_via_gmail_api(email, code)
        if not success:
            success = send_verification_via_smtp(email, code)
        
        return success
    except Exception as e:
        print(f"Error sending verification email: {e}")
        return False

def send_verification_via_gmail_api(email, code):
    """Send verification email using Gmail API"""
    try:
        # Gmail API credentials should be in environment or credentials file
        gmail_user = os.getenv('GMAIL_USER')
        
        if not gmail_user:
            return False
            
        # Create the email message
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = "CultureQuest - Email Verification Code"
        
        # Email body with professional template
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #4a90e2;">CultureQuest</h1>
                    <p style="color: #666;">Email Verification</p>
                </div>
                
                <div style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h2 style="color: #4a90e2; margin-top: 0;">Verify Your Email Address</h2>
                    <p>Welcome to CultureQuest! Please use the verification code below to complete your account setup:</p>
                    
                    <div style="text-align: center; margin: 25px 0;">
                        <div style="font-size: 32px; font-weight: bold; color: #4a90e2; background: white; padding: 15px; border-radius: 8px; letter-spacing: 5px; display: inline-block; border: 2px dashed #4a90e2;">
                            {code}
                        </div>
                    </div>
                    
                    <p><strong>This code will expire in 15 minutes.</strong></p>
                    <p>If you didn't create an account with CultureQuest, please ignore this email.</p>
                </div>
                
                <div style="text-align: center; color: #666; font-size: 12px;">
                    <p>This email was sent by CultureQuest</p>
                    <p>Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Note: Gmail API implementation would go here
        # For now, fall back to SMTP
        return False
        
    except Exception as e:
        print(f"Gmail API error: {e}")
        return False

def send_verification_via_smtp(email, code):
    """Send verification email using SMTP (Gmail)"""
    try:
        # Get Gmail credentials from environment variables
        gmail_user = os.getenv('GMAIL_USER')
        gmail_password = os.getenv('GMAIL_APP_PASSWORD')  # Use App Password, not regular password
        
        if not gmail_user or not gmail_password:
            print("Gmail credentials not found in environment variables")
            return False
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = "CultureQuest - Email Verification Code"
        
        # Email body with professional template
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #4a90e2;">CultureQuest</h1>
                    <p style="color: #666;">Email Verification</p>
                </div>
                
                <div style="background: #f9f9f9; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                    <h2 style="color: #4a90e2; margin-top: 0;">Verify Your Email Address</h2>
                    <p>Welcome to CultureQuest! Please use the verification code below to complete your account setup:</p>
                    
                    <div style="text-align: center; margin: 25px 0;">
                        <div style="font-size: 32px; font-weight: bold; color: #4a90e2; background: white; padding: 15px; border-radius: 8px; letter-spacing: 5px; display: inline-block; border: 2px dashed #4a90e2;">
                            {code}
                        </div>
                    </div>
                    
                    <p><strong>This code will expire in 15 minutes.</strong></p>
                    <p>If you didn't create an account with CultureQuest, please ignore this email.</p>
                </div>
                
                <div style="text-align: center; color: #666; font-size: 12px;">
                    <p>This email was sent by CultureQuest</p>
                    <p>Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>"""
        
        msg.attach(MIMEText(body, 'html'))
        
        # Gmail SMTP settings
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_password)
        
        # Send email
        text = msg.as_string()
        server.sendmail(gmail_user, email, text)
        server.quit()
        
        print(f"Verification email sent successfully to {email}")
        return True
        
    except Exception as e:
        print(f"SMTP error: {e}")
        return False

def send_reset_email(email, code):
    """Send password reset email using Gmail API or SMTP"""
    try:
        # Clean up expired codes first
        cleanup_expired_codes()
        
        # Try Gmail API first, then fallback to SMTP
        success = send_via_gmail_api(email, code)
        if not success:
            success = send_via_smtp(email, code)
        
        return success
    except Exception as e:
        print(f"Error sending reset email: {e}")
        return False

def send_via_gmail_api(email, code):
    """Send email using Gmail API"""
    try:
        # Gmail API credentials should be in environment or credentials file
        gmail_user = os.getenv('GMAIL_USER')
        
        if not gmail_user:
            return False
            
        # Create the email message
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = "CultureQuest - Password Reset Code"
        
        # Email body
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2 style="color: #4a90e2;">🔑 CultureQuest Password Reset</h2>
                </div>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0; color: #2c3e50;">Your verification code is:</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #4a90e2; text-align: center; background: white; padding: 15px; border-radius: 8px; letter-spacing: 8px; margin: 20px 0;">
                        {code}
                    </div>
                    <p style="color: #666; font-size: 14px; text-align: center;">
                        This code will expire in 15 minutes for security reasons.
                    </p>
                </div>
                
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <p style="margin: 0; color: #856404;">🛡️ <strong>Security Notice:</strong></p>
                    <ul style="color: #856404; margin: 10px 0;">
                        <li>Never share this code with anyone</li>
                        <li>CultureQuest will never ask for this code via phone or email</li>
                        <li>If you didn't request this reset, you can safely ignore this email</li>
                    </ul>
                </div>
                
                <div style="text-align: center; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px;">
                    <p>This email was sent from CultureQuest Password Reset System</p>
                    <p>© 2024 CultureQuest. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Try to use Gmail API (requires proper setup)
        # For now, fallback to SMTP
        return False
        
    except Exception as e:
        print(f"Gmail API error: {e}")
        return False

def send_via_smtp(email, code):
    """Send email using SMTP (Gmail)"""
    try:
        # Get Gmail credentials from environment variables
        gmail_user = os.getenv('GMAIL_USER')
        gmail_password = os.getenv('GMAIL_APP_PASSWORD')  # Use App Password, not regular password
        
        if not gmail_user or not gmail_password:
            print("Gmail credentials not found in environment variables")
            return False
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = gmail_user
        msg['To'] = email
        msg['Subject'] = "CultureQuest - Password Reset Code"
        
        # Email body
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h2 style="color: #4a90e2;">🔑 CultureQuest Password Reset</h2>
                </div>
                
                <div style="background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 20px;">
                    <h3 style="margin-top: 0; color: #2c3e50;">Your verification code is:</h3>
                    <div style="font-size: 32px; font-weight: bold; color: #4a90e2; text-align: center; background: white; padding: 15px; border-radius: 8px; letter-spacing: 8px; margin: 20px 0;">
                        {code}
                    </div>
                    <p style="color: #666; font-size: 14px; text-align: center;">
                        This code will expire in 15 minutes for security reasons.
                    </p>
                </div>
                
                <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
                    <p style="margin: 0; color: #856404;">🛡️ <strong>Security Notice:</strong></p>
                    <ul style="color: #856404; margin: 10px 0;">
                        <li>Never share this code with anyone</li>
                        <li>CultureQuest will never ask for this code via phone or email</li>
                        <li>If you didn't request this reset, you can safely ignore this email</li>
                    </ul>
                </div>
                
                <div style="text-align: center; padding-top: 20px; border-top: 1px solid #eee; color: #666; font-size: 12px;">
                    <p>This email was sent from CultureQuest Password Reset System</p>
                    <p>© 2024 CultureQuest. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        # Gmail SMTP setup
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(gmail_user, gmail_password)
        
        # Send email
        text = msg.as_string()
        server.sendmail(gmail_user, email, text)
        server.quit()
        
        print(f"Password reset email sent successfully to {email}")
        return True
        
    except Exception as e:
        print(f"SMTP error: {e}")
        return False

# Admin decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'is_admin' not in session or not session['is_admin']:
            flash('Admin access required.', 'danger')
            return redirect(url_for('login.login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@login_bp.route('/')
def landing_page():
    """Landing page"""
    return render_template('landing.html')

@login_bp.route('/login')
def login_page():
    """Login page"""
    return render_template('login.html')

# Only register this fallback route if Google OAuth is not configured
if not os.getenv('GOOGLE_CLIENT_ID') or not os.getenv('GOOGLE_CLIENT_SECRET'):
    @login_bp.route('/auth/google')
    def google_login_not_configured():
        """Handle Google login when not configured"""
        print("DEBUG: Google OAuth not configured - showing error message")
        print(f"DEBUG: GOOGLE_CLIENT_ID exists: {bool(os.getenv('GOOGLE_CLIENT_ID'))}")
        print(f"DEBUG: GOOGLE_CLIENT_SECRET exists: {bool(os.getenv('GOOGLE_CLIENT_SECRET'))}")
        flash('Google login is not configured. You need to set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file.', 'error')
        return redirect(url_for('login.login_page'))



@login_bp.route('/signup', methods=['GET'])
def signup_page():
    """Regular signup page"""
    return render_template('signup.html')

@login_bp.route('/signup', methods=['POST'])
def signup():
    """Handle regular signup form submission"""
    # Check if request is JSON or form data
    if request.is_json:
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
    else:
        # Handle form data (this is what your HTML form sends)
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
    
    # Validate required fields
    if not username or not email or not password:
        if request.is_json:
            return jsonify({'success': False, 'message': 'All fields are required'})
        else:
            flash('All fields are required', 'danger')
            return redirect(url_for('login.signup_page'))
    
    # Check if user already exists
    if find_user_by_email(email):
        if request.is_json:
            return jsonify({'success': False, 'message': 'Email already registered'})
        else:
            flash('Email already registered', 'danger')
            return redirect(url_for('login.signup_page'))
    
    if find_user_by_username(username):
        if request.is_json:
            return jsonify({'success': False, 'message': 'Username already taken'})
        else:
            flash('Username already taken', 'danger')
            return redirect(url_for('login.signup_page'))
    
    # Generate verification code and store user data temporarily
    verification_code = generate_verification_code()
    user_data = {
        'username': username,
        'email': email,
        'password': password,
        'is_google_user': False,
        'profile_picture': None
    }
    
    # Store verification code with user data
    print(f"DEBUG: Storing verification code for {email}")
    if store_verification_code(email, verification_code, user_data):
        print(f"DEBUG: Verification code stored successfully")
        # Send verification email
        if send_verification_email(email, verification_code):
            print(f"DEBUG: Verification email sent successfully, redirecting to verify page")
            # Check if this is an AJAX request (from signup.html JavaScript)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': True, 
                    'message': 'Verification email sent',
                    'redirect_url': url_for('login.verify_email_page', email=email)
                })
            elif request.is_json:
                return jsonify({'success': True, 'message': 'Verification email sent'})
            else:
                flash('Verification code sent to your email. Please check your inbox.', 'success')
                return redirect(url_for('login.verify_email_page', email=email))
        else:
            if request.is_json:
                return jsonify({'success': False, 'message': 'Failed to send verification email'})
            else:
                flash('Failed to send verification email. Please try again.', 'danger')
                return redirect(url_for('login.signup_page'))
    else:
        if request.is_json:
            return jsonify({'success': False, 'message': 'Error processing signup'})
        else:
            flash('Error processing signup. Please try again.', 'danger')
            return redirect(url_for('login.signup_page'))

@login_bp.route('/signup2', methods=['GET'])
def signup2_page():
    """Google user signup page (after Google OAuth)"""
    if 'google_email' not in session:
        flash("Please log in with Google first.", "warning")
        return redirect(url_for('login.login_page'))
    
    # Clear any previous flash messages to avoid showing irrelevant messages
    session.pop('_flashes', None)
    
    email = session.get('google_email')
    return render_template('signup2.html', email=email)

@login_bp.route('/signup2', methods=['POST'])
def signup2():
    """Handle Google user signup form submission"""
    # Check if it's an AJAX request (from JavaScript)
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    if 'google_email' not in session:
        if is_ajax:
            return jsonify({'error': 'Session expired. Please log in again.'}), 401
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for('login.login_page'))
    
    # Get form data
    username = request.form.get('username')
    password = request.form.get('password')
    
    email = session.get('google_email')
    # Use default profile picture instead of Google profile picture
    profile_picture = 'default_picture.png'
    
    if not username or not password:
        if is_ajax:
            return jsonify({'error': 'Username and password are required'}), 400
        flash('Username and password are required', 'danger')
        return redirect(url_for('login.signup2_page'))
    
    # Check if username already exists
    if find_user_by_username(username):
        if is_ajax:
            return jsonify({'error': 'Username already taken'}), 400
        flash('Username already taken', 'danger')
        return redirect(url_for('login.signup2_page'))
    
    # Check if email already exists
    if find_user_by_email(email):
        if is_ajax:
            return jsonify({'error': 'Email already registered'}), 400
        flash('Email already registered', 'danger')
        return redirect(url_for('login.signup2_page'))
    
    # Create new Google user
    new_user = create_user(username, email, password, is_google_user=True, profile_picture=profile_picture, email_verified=True)
    
    if new_user:
        # Set session for login
        session['username'] = username
        session['email'] = email
        session['profile_picture'] = 'default_picture.png'
        session['user_id'] = new_user['id']
        session['is_admin'] = False
        
        # Clear temporary Google session data
        session.pop('google_email', None)
        session.pop('google_name', None)
        session.pop('google_profile_picture', None)
        
        if is_ajax:
            return jsonify({
                'success': True,
                'message': 'Account created successfully!',
                'redirect_url': url_for('login.profile')
            })
        flash('Account created successfully!', 'success')
        return redirect(url_for('login.profile'))
    else:
        if is_ajax:
            return jsonify({'error': 'Error creating account. Please try again.'}), 500
        flash('Error creating account. Please try again.', 'danger')
        return redirect(url_for('login.signup2_page'))

@login_bp.route('/login', methods=['POST'])
def login():
    """Handle login form submission"""
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Username and password are required!", "danger")
        return redirect(url_for('login.login_page'))

    # Check for admin login
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session['username'] = username
        session['is_admin'] = True
        flash("Welcome, Admin!", "success")
        return redirect(url_for('login.admin_dashboard'))

    # Check regular user login
    user = find_user_by_username(username)

    if user and user.get('password') and check_password_hash(user['password'], password):
        # Update last login time
        update_user_login_time(username)
        
        session['username'] = username
        session['email'] = user['email']
        session['profile_picture'] = user.get('profile_picture')
        session['user_id'] = user['id']
        session['is_admin'] = False
        
        flash(f"Welcome back, {username}!", "success")
        return redirect(url_for('login.profile'))
    else:
        flash("Invalid credentials!", "danger")
        return redirect(url_for('login.login_page'))

@login_bp.route('/profile')
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
    return redirect(url_for('login.login_page'))

@login_bp.route('/update-profile', methods=['POST'])
def update_profile():
    """Update user profile"""
    if 'username' not in session or session.get('is_admin', False):
        return redirect(url_for('login.login_page'))

    user_id = session.get('user_id')
    if not user_id:
        flash('Session error. Please log in again.', 'danger')
        return redirect(url_for('login.login_page'))

    # Get form data
    online_start_time = request.form.get('online_start_time')
    online_end_time = request.form.get('online_end_time')
    occupation = request.form.get('occupation')
    birthday = request.form.get('birthday')
    labels = request.form.get('labels')

    updates = {}
    
    # Format time fields
    if online_start_time and online_end_time:
        try:
            start_time_obj = datetime.strptime(online_start_time, '%H:%M')
            end_time_obj = datetime.strptime(online_end_time, '%H:%M')
            formatted_start_time = start_time_obj.strftime('%I:%M%p').lower()
            formatted_end_time = end_time_obj.strftime('%I:%M%p').lower()
            updates['online_start_time'] = formatted_start_time
            updates['online_end_time'] = formatted_end_time
        except ValueError:
            flash('Invalid time format', 'danger')
            return redirect(url_for('login.profile'))
    else:
        updates['online_start_time'] = None
        updates['online_end_time'] = None

    # Update other fields
    if occupation:
        updates['occupation'] = occupation.strip()
    if birthday:
        updates['birthday'] = birthday
    if labels:
        updates['labels'] = labels.strip()

    # Save updates
    if update_user(user_id, updates):
        flash('Profile updated successfully!', 'success')
    else:
        flash('Error updating profile. Please try again.', 'danger')
    
    return redirect(url_for('login.profile'))

@login_bp.route('/logout')
def logout():
    """Logout user"""
    session.clear()  # Clear all session data
    flash("You have been logged out.", "info")
    return redirect(url_for('login.login_page'))

@login_bp.route('/auth/google/callback')
def google_callback():
    """Handle Google OAuth callback"""
    print("Google callback triggered")
    
    if not google.authorized:
        print("Not authorized with Google")
        flash("Authorization failed. Please try again.", "danger")
        return redirect(url_for('login.login_page'))
    
    try:
        print("Fetching user info from Google...")
        # Get user data from Google
        user_info = google.get('/oauth2/v2/userinfo')
        
        if not user_info.ok:
            print(f"Google API Error: {user_info.status_code} - {user_info.text}")
            flash("Failed to fetch user info from Google.", "danger")
            return redirect(url_for('login.login_page'))

        user_data = user_info.json()
        print(f"Google user data received: {user_data}")
        
        email = user_data.get('email')
        name = user_data.get('name')
        profile_picture = user_data.get('picture')

        if not email or not name:
            print("Missing email or name from Google")
            flash("Missing user information from Google.", "danger")
            return redirect(url_for('login.login_page'))

        # Check if user exists
        existing_user = find_user_by_email(email)

        if existing_user and existing_user.get('username') and existing_user.get('password'):
            # User exists and has completed signup - log them in
            print(f"Existing user found with complete profile: {existing_user['username']}")
            
            # Update last login time
            update_user_login_time(existing_user['username'])
            
            # Set session data for existing user
            session['username'] = existing_user['username']
            session['email'] = existing_user['email']
            # Use default picture if no custom profile picture is set
            session['profile_picture'] = existing_user.get('profile_picture') or 'default_picture.png'
            session['user_id'] = existing_user['id']
            session['is_admin'] = False
            
            flash(f"Welcome back, {existing_user['username']}!", "success")
            return redirect(url_for('login.profile'))
        else:
            # New user or Google user without username/password - redirect to signup2
            print(f"New Google user or incomplete profile for: {email}")
            
            # Store Google info in session for signup2
            session['google_email'] = email
            session['google_name'] = name
            session['google_profile_picture'] = profile_picture
            
            flash(f"Welcome! Please complete your account setup.", "info")
            return redirect(url_for('login.signup2_page'))

    except Exception as e:
        print(f"Exception in google_callback: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f"An error occurred during Google login: {str(e)}", "danger")
        return redirect(url_for('login.login_page'))

# Password Reset Routes
@login_bp.route('/forgot-password', methods=['GET'])
def forgot_password_page():
    """Forgot password page"""
    return render_template('forget.html')

@login_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Handle forgot password form submission"""
    email = request.form.get('email')
    
    if not email:
        flash('Email address is required', 'error')
        return redirect(url_for('login.forgot_password_page'))
    
    # Validate email format
    import re
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        flash('Please enter a valid email address', 'error')
        return redirect(url_for('login.forgot_password_page'))
    
    # Check if user exists
    user = find_user_by_email(email)
    if not user:
        # For security, don't reveal whether email exists or not
        flash('If an account with this email exists and is verified, a verification code has been sent.', 'success')
        return redirect(url_for('login.forgot_password_page'))
    
    # Check if email is verified
    if not user.get('email_verified', False):
        # For security, don't reveal specific reason - use same message
        flash('If an account with this email exists and is verified, a verification code has been sent.', 'success')
        return redirect(url_for('login.forgot_password_page'))
    
    # Check if user is Google user (they should reset via Google)
    if user.get('is_google_user', False):
        # For security, don't reveal specific reason - use same message but suggest Google
        flash('If an account with this email exists and is verified, a verification code has been sent. If you signed up with Google, please use Google\'s password recovery.', 'info')
        return redirect(url_for('login.forgot_password_page'))
    
    # Generate and store reset code
    reset_code = generate_reset_code()
    
    if not store_reset_code(email, reset_code):
        flash('Error generating reset code. Please try again.', 'error')
        return redirect(url_for('login.forgot_password_page'))
    
    # Send reset email
    if send_reset_email(email, reset_code):
        flash('A 6-digit verification code has been sent to your email address.', 'success')
        # Store email in session for verification step
        session['reset_email'] = email
        return redirect(url_for('login.verify_reset_code_page'))
    else:
        flash('Error sending reset email. Please check your email configuration.', 'error')
        return redirect(url_for('login.forgot_password_page'))

@login_bp.route('/verify-code', methods=['GET'])
def verify_reset_code_page():
    """Verify reset code page"""
    if 'reset_email' not in session:
        flash('Please request a password reset first.', 'warning')
        return redirect(url_for('login.forgot_password_page'))
    
    return render_template('verify_code.html', email=session['reset_email'])

@login_bp.route('/verify-code', methods=['POST'])
def verify_reset_code():
    """Handle reset code verification"""
    if 'reset_email' not in session:
        flash('Session expired. Please request a new reset code.', 'error')
        return redirect(url_for('login.forgot_password_page'))
    
    email = session['reset_email']
    code = request.form.get('code')
    
    if not code:
        flash('Verification code is required', 'error')
        return redirect(url_for('login.verify_reset_code_page'))
    
    # Verify the code
    is_valid, message = verify_reset_code_helper(email, code)
    
    if is_valid:
        # Code is valid, proceed to password reset
        session['code_verified'] = True
        flash('Code verified successfully. Please enter your new password.', 'success')
        return redirect(url_for('login.reset_password_page'))
    else:
        flash(message, 'error')
        return redirect(url_for('login.verify_reset_code_page'))

@login_bp.route('/reset-password', methods=['GET'])
def reset_password_page():
    """Reset password page"""
    if 'reset_email' not in session or 'code_verified' not in session:
        flash('Please complete the verification process first.', 'warning')
        return redirect(url_for('login.forgot_password_page'))
    
    return render_template('reset_password.html', email=session['reset_email'])

@login_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Handle password reset"""
    if 'reset_email' not in session or 'code_verified' not in session:
        flash('Session expired. Please start the reset process again.', 'error')
        return redirect(url_for('login.forgot_password_page'))
    
    email = session['reset_email']
    new_password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    
    if not new_password or not confirm_password:
        flash('Both password fields are required', 'error')
        return redirect(url_for('login.reset_password_page'))
    
    if new_password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('login.reset_password_page'))
    
    # Validate password strength
    if len(new_password) < 8:
        flash('Password must be at least 8 characters long', 'error')
        return redirect(url_for('login.reset_password_page'))
    
    # Find user and update password
    user = find_user_by_email(email)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login.forgot_password_page'))
    
    # Update password
    new_password_hash = generate_password_hash(new_password)
    if update_user(user['id'], {'password': new_password_hash}):
        # Clear session data
        session.pop('reset_email', None)
        session.pop('code_verified', None)
        
        flash('Password reset successfully! You can now log in with your new password.', 'success')
        return redirect(url_for('login.login_page'))
    else:
        flash('Error updating password. Please try again.', 'error')
        return redirect(url_for('login.reset_password_page'))

@login_bp.route('/resend-code', methods=['POST'])
def resend_reset_code():
    """Resend reset code"""
    if 'reset_email' not in session:
        return jsonify({'success': False, 'message': 'Session expired'})
    
    email = session['reset_email']
    
    # Generate new code
    reset_code = generate_reset_code()
    
    if not store_reset_code(email, reset_code):
        return jsonify({'success': False, 'message': 'Error generating reset code'})
    
    # Send reset email
    if send_reset_email(email, reset_code):
        return jsonify({'success': True, 'message': 'New verification code sent successfully'})
    else:
        return jsonify({'success': False, 'message': 'Error sending reset email'})

# Email Verification Routes
@login_bp.route('/verify-email', methods=['GET'])
def verify_email_page():
    """Email verification page"""
    email = request.args.get('email')
    print(f"DEBUG: verify_email_page called with email: {email}")
    
    if not email:
        flash('No email specified for verification', 'error')
        return redirect(url_for('login.signup_page'))
    
    # Check if verification code exists for this email
    connection = get_db_connection()
    if not connection:
        flash('Database connection failed', 'error')
        return redirect(url_for('login.signup_page'))
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM verification_codes WHERE email = %s", (email,))
            code_data = cursor.fetchone()
            
        if not code_data:
            flash('No verification code found. Please sign up again.', 'error')
            return redirect(url_for('login.signup_page'))
    finally:
        connection.close()
    
    print(f"DEBUG: Rendering verify-email.html for {email}")
    return render_template('verify-email.html', email=email)

@login_bp.route('/verify-email', methods=['POST'])
def verify_email():
    """Handle email verification code submission"""
    email = request.form.get('email')
    verification_code = request.form.get('verification_code')
    
    if not email or not verification_code:
        flash('Email and verification code are required', 'error')
        return redirect(url_for('login.verify_email_page', email=email))
    
    # Verify the code
    success, message, user_data = verify_email_code_helper(email, verification_code)
    
    if success and user_data:
        # Create the user account now that email is verified
        new_user = create_user(
            user_data['username'], 
            user_data['email'], 
            user_data['password'], 
            user_data.get('is_google_user', False),
            user_data.get('profile_picture'),
            email_verified=True
        )
        
        if new_user:
            flash('Email verified successfully! Your account has been created. Please log in.', 'success')
            return redirect(url_for('login.login_page'))
        else:
            flash('Error creating account after verification. Please contact support.', 'error')
            return redirect(url_for('login.signup_page'))
    else:
        flash(message, 'error')
        return redirect(url_for('login.verify_email_page', email=email))

@login_bp.route('/resend-code')
def resend_code():
    """Resend verification code"""
    email = request.args.get('email')
    if not email:
        flash('No email specified', 'error')
        return redirect(url_for('login.signup_page'))
    
    # Check if verification code exists for this email
    connection = get_db_connection()
    if not connection:
        flash('Database connection failed', 'error')
        return redirect(url_for('login.signup_page'))
    
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM verification_codes WHERE email = %s", (email,))
            code_data = cursor.fetchone()
            
        if not code_data:
            flash('No verification code found. Please sign up again.', 'error')
            return redirect(url_for('login.signup_page'))
        
        # Get existing user data
        import json
        user_data = json.loads(code_data['user_data']) if code_data['user_data'] else None
        if not user_data:
            flash('Invalid verification session. Please sign up again.', 'error')
            return redirect(url_for('login.signup_page'))
    finally:
        connection.close()
    
    # Generate new verification code
    new_code = generate_verification_code()
    
    # Update the stored code
    if store_verification_code(email, new_code, user_data):
        # Send new verification email
        if send_verification_email(email, new_code):
            flash('A new verification code has been sent to your email.', 'success')
        else:
            flash('Failed to send verification email. Please try again.', 'error')
    else:
        flash('Error generating new verification code. Please try again.', 'error')
    
    return redirect(url_for('login.verify_email_page', email=email))

# API Routes
@login_bp.route('/api/security-tokens', methods=['GET'])
def get_security_tokens():
    """Generate security tokens for forms"""
    try:
        # Generate CSRF token
        csrf_token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        
        # Generate form token
        form_token = ''.join(random.choices(string.ascii_letters + string.digits, k=24))
        
        # Generate session ID if not exists
        if 'session_id' not in session:
            session['session_id'] = str(uuid.uuid4())
        
        # Store tokens in session for validation
        session['csrf_token'] = csrf_token
        session['form_token'] = form_token
        
        return jsonify({
            'success': True,
            'csrf_token': csrf_token,
            'form_token': form_token,
            'session_id': session['session_id'],
            'timestamp': str(int(datetime.now().timestamp()))
        })
    except Exception as e:
        print(f"Error generating security tokens: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to generate security tokens'
        }), 500

@login_bp.route('/api/captcha', methods=['GET'])
def get_captcha():
    """Generate CAPTCHA for signup form"""
    try:
        # Generate random CAPTCHA code
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        captcha = ''.join(random.choices(chars, k=6))
        
        return jsonify({
            'success': True,
            'captcha': captcha
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': 'Failed to generate CAPTCHA'
        }), 500

@login_bp.route('/api/check-username', methods=['POST'])
def check_username_availability():
    """Check if username is available"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({
                'success': False,
                'available': False,
                'message': 'Username is required'
            })
        
        # Basic format validation
        if len(username) < 3:
            return jsonify({
                'success': True,
                'available': False,
                'message': 'Username too short (min 3 chars)'
            })
        
        if len(username) > 30:
            return jsonify({
                'success': True,
                'available': False,
                'message': 'Username too long (max 30 chars)'
            })
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            return jsonify({
                'success': True,
                'available': False,
                'message': 'Only letters, numbers, and underscores allowed'
            })
        
        if re.match(r'^[0-9]+$', username):
            return jsonify({
                'success': True,
                'available': False,
                'message': 'Username cannot be all numbers'
            })
        
        # Check if username already exists in database
        existing_user = find_user_by_username(username)
        if existing_user:
            return jsonify({
                'success': True,
                'available': False,
                'message': 'Username is already taken'
            })
        
        # Username is available
        return jsonify({
            'success': True,
            'available': True,
            'message': 'Username is available'
        })
        
    except Exception as e:
        print(f"Error checking username: {e}")
        return jsonify({
            'success': False,
            'available': False,
            'message': 'Error checking username'
        }), 500

# Admin Routes
@login_bp.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard"""
    # Get statistics
    stats = get_user_stats()
    
    # Get recent users (last 10)
    users = load_users()
    recent_users = sorted(users, key=lambda x: x.get('created_at', ''), reverse=True)[:10]
    
    # Get all users for the table
    all_users = sorted(users, key=lambda x: x.get('created_at', ''), reverse=True)
    
    return render_template('admin_dashboard.html', 
                         total_users=stats['total_users'],
                         google_users=stats['google_users'],
                         regular_users=stats['regular_users'],
                         users_today=stats['users_today'],
                         users_this_week=stats['users_this_week'],
                         recent_users=recent_users,
                         all_users=all_users)

@login_bp.route('/admin/user/<user_id>')
@admin_required
def admin_user_detail(user_id):
    """Admin user detail page"""
    user = find_user_by_id(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login.admin_dashboard'))
    return render_template('admin_user_detail.html', user=user)

@login_bp.route('/admin/user/<user_id>/delete', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Admin delete user"""
    user = find_user_by_id(user_id)
    if user:
        if delete_user_by_id(user_id):
            flash(f'User {user["username"]} has been deleted successfully.', 'success')
        else:
            flash('Error deleting user. Please try again.', 'danger')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('login.admin_dashboard'))

@login_bp.route('/admin/users/export')
@admin_required
def admin_export_users():
    """Export users to CSV"""
    import csv
    from io import StringIO
    from flask import make_response
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['ID', 'Username', 'Email', 'Is Google User', 'Occupation', 
                     'Birthday', 'Labels', 'Online Start', 'Online End', 
                     'Created At', 'Last Login'])
    
    # Write user data
    users = load_users()
    for user in users:
        writer.writerow([
            user.get('id', ''),
            user.get('username', ''),
            user.get('email', ''),
            user.get('is_google_user', False),
            user.get('occupation', ''),
            user.get('birthday', ''),
            user.get('labels', ''),
            user.get('online_start_time', ''),
            user.get('online_end_time', ''),
            user.get('created_at', ''),
            user.get('last_login', '')
        ])
    
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=users_export.csv'
    
    return response

# Initialize database when blueprint is imported
try:
    init_database()
except Exception as e:
    print(f"Warning: Could not initialize database on import: {e}")

# No error handlers - let Flask handle errors naturally