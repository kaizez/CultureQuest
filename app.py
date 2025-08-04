import os
import sys
import uuid
import pymysql
from flask import Flask, render_template, send_from_directory, abort, session
from flask_socketio import SocketIO
from dotenv import load_dotenv
from jinja2 import FileSystemLoader, ChoiceLoader

# Add current directory and module directories to Python path for proper imports
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.join(current_dir, 'challenge'))
sys.path.insert(0, os.path.join(current_dir, 'chatapp_rewards'))  
sys.path.insert(0, os.path.join(current_dir, 'login'))

# Import blueprints from each module
# Change working directory temporarily to import from each module
import os
old_cwd = os.getcwd()

# Import shared database
from shared_db import db

# Import challenge module
os.chdir(os.path.join(current_dir, 'challenge'))
from db_handler import RateLimit
from challenge import challenge_bp
from admin_screening import admin_screening_bp
from event import event_bp
from challenge_models import db

# Import chatapp_rewards module
os.chdir(os.path.join(current_dir, 'chatapp_rewards'))
from chat import chat_bp, handle_join, handle_leave, handle_chat_message
from chat_manage import chat_manage_bp
from rewards import rewards_bp
from models import ChatRoom, RewardItem, UserPoints

# Import login module
os.chdir(os.path.join(current_dir, 'login'))
import sys
login_module_path = os.path.join(current_dir, 'login', 'login.py')
import importlib.util
spec = importlib.util.spec_from_file_location("login_module", login_module_path)
login_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(login_module)
login_bp = login_module.login_bp
google_bp = login_module.google_bp
init_database = login_module.init_database


# Import chatapp_rewards module
os.chdir(os.path.join(current_dir, 'response'))
from response import response_bp
#from mod import moderate_bp

# Restore original working directory
os.chdir(old_cwd)

def load_env():
    """Load environment variables from .env file."""
    basedir = os.getcwd()
    dotenv_path = os.path.join(basedir, '.env')
    if os.path.exists(dotenv_path):
        print(f"Loading .env file from {dotenv_path}")
        load_dotenv(dotenv_path)
        
        # Debug: Check if API key is loaded
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if api_key:
            print(f"[OK] VirusTotal API key loaded (length: {len(api_key)})")
        else:
            print("[WARNING] VirusTotal API key not found in environment")
    else:
        print("Warning: .env file not found.")
        print(f"Looking for .env at: {dotenv_path}")

# Load environment variables
load_env()

# Initialize the Flask app
app = Flask(__name__, static_url_path='/static', static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production-' + str(uuid.uuid4()))

# Configure multiple template directories
template_loaders = [
    FileSystemLoader(os.path.join(current_dir, 'challenge/templates')),
    FileSystemLoader(os.path.join(current_dir, 'chatapp_rewards/templates')),  
    FileSystemLoader(os.path.join(current_dir, 'login/public'))
]
app.jinja_loader = ChoiceLoader(template_loaders)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')

# Configure OAuth settings
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', 'False').lower() == 'true'
app.config['OAUTHLIB_RELAX_TOKEN_SCOPE'] = True

# Force HTTPS and correct hostname for OAuth redirects
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SERVER_NAME'] = os.environ.get('OAUTH_HOSTNAME', '127.0.0.1:5000')

# Build database URI from individual environment variables
db_host = os.environ.get('DB_HOST')
db_port = os.environ.get('DB_PORT')
db_user = os.environ.get('DB_USER')
db_password = os.environ.get('DB_PASSWORD')
db_name = os.environ.get('DB_NAME')

if not all([db_host, db_port, db_user, db_password, db_name]):
    print("Warning: Database environment variables not found. Please check your .env file.")
    print("Required variables: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
    print(f"[OK] Connected to MySQL database: {db_host}:{db_port}/{db_name}")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize extensions
db.init_app(app)
socketio = SocketIO(app)

# Make auth functions available to all templates
from chatapp_rewards.auth_utils import get_navbar_template

@app.context_processor
def inject_navbar():
    return dict(get_navbar_template=get_navbar_template)

# Create tables if not exist
with app.app_context():
    try:
        db.create_all()
        print("[OK] All database tables created/verified")
        
        # Verify that chatapp_rewards tables have the correct schema
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        
        # Check Message table has user_id column
        message_columns = [col['name'] for col in inspector.get_columns('message')]
        if 'user_id' not in message_columns:
            print("[WARNING] Message table missing user_id column - may need to run clear_user_data.py")
        
        # Check MutedUser table has user_id column  
        try:
            muted_user_columns = [col['name'] for col in inspector.get_columns('muted_user')]
            if 'user_id' not in muted_user_columns:
                print("[WARNING] MutedUser table missing user_id column - may need to run clear_user_data.py")
        except:
            pass  # Table might not exist yet
            
        # Check UserPoints table has user_id column
        try:
            user_points_columns = [col['name'] for col in inspector.get_columns('user_points')]
            if 'user_id' not in user_points_columns:
                print("[WARNING] UserPoints table missing user_id column - may need to run clear_user_data.py")
        except:
            pass  # Table might not exist yet
            
    except Exception as e:
        print(f"[ERROR] Database initialization failed: {e}")
        print("[INFO] If you're seeing schema errors, run: python clear_user_data.py")
    
    # Create default chat rooms if they don't exist
    if ChatRoom.query.count() == 0:
        default_rooms = [
            ChatRoom(name="General Chat", description="Welcome to the general discussion room"),
            ChatRoom(name="Tech Talk", description="Discuss technology, programming, and innovation"),
            ChatRoom(name="Random", description="Talk about anything and everything"),
            ChatRoom(name="File Sharing", description="Share and discuss files securely")
        ]
        
        for room in default_rooms:
            db.session.add(room)
        db.session.commit()
        print("[OK] Default chat rooms created")
    
    # Create default reward items if they don't exist
    if RewardItem.query.count() == 0:
        default_rewards = [
            RewardItem(
                name="$1 Voucher",
                description="A $1 discount voucher for your next purchase",
                cost=100,
                stock=9999999,
                is_active=True
            ),
            RewardItem(
                name="Reusable Bag",
                description="Eco-friendly reusable bag with stylish motorcycle design",
                cost=300,
                stock=2,
                is_active=True
            ),
            RewardItem(
                name="Eco-friendly Plush",
                description="Soft and cuddly eco-friendly plush toy made from recycled materials",
                cost=500,
                stock=49,
                is_active=True
            ),
            RewardItem(
                name="Keychain",
                description="Stylish motorcycle helmet keychain",
                cost=150,
                stock=10,
                is_active=True
            ),
            RewardItem(
                name="Tree Donation",
                description="Plant a tree in your name to help the environment",
                cost=100,
                stock=999999,
                is_active=True
            )
        ]
        
        for reward in default_rewards:
            db.session.add(reward)
        db.session.commit()
        print("[OK] Default reward items created")

# Register Blueprints without URL prefixes so routes are accessible directly
# Challenge module blueprints
app.register_blueprint(challenge_bp, url_prefix='/challenge_form')  # Keep /host for challenge routes
app.register_blueprint(admin_screening_bp, url_prefix='/admin/dashboard/screening')  # Keep /admin for admin routes  
app.register_blueprint(event_bp, url_prefix='/event')  # Keep /event for event routes

# Chat/Rewards module blueprints - remove prefixes to make routes accessible directly
app.register_blueprint(chat_bp)  # This will make /chat routes accessible directly
app.register_blueprint(chat_manage_bp)  # This will make chat management routes accessible  
app.register_blueprint(rewards_bp)  # This will make /rewards routes accessible directly

# Login module blueprints
app.register_blueprint(login_bp)  # Login routes accessible directly

# Challenge response blueprints
app.register_blueprint(response_bp, url_prefix='/response')
#app.register_blueprint(moderate_bp, url_prefix='/moderate')

# Register Google blueprint if it was created (i.e., if credentials are available)
if google_bp is not None:
    app.register_blueprint(google_bp, url_prefix='/auth')
    app.config['GOOGLE_OAUTH_ENABLED'] = True
else:
    app.config['GOOGLE_OAUTH_ENABLED'] = False

# Static files are now served automatically by Flask from the 'static' folder

# Handle uploaded files from challenge module specifically
@app.route('/uploads/<filename>')
def serve_challenge_uploads(filename):
    """Serve uploaded files from challenge module"""
    upload_path = os.path.join(current_dir, 'challenge/static/uploads')
    if os.path.exists(os.path.join(upload_path, filename)):
        return send_from_directory(upload_path, filename)
    abort(404)


# SocketIO event handlers for chat functionality
@socketio.on('join')
def on_join(data):
    """Handle user joining a chat room"""
    handle_join(socketio, data)

@socketio.on('leave')
def on_leave(data):
    """Handle user leaving a chat room"""
    handle_leave(socketio, data)

@socketio.on('my event')
def handle_my_custom_event(json):
    """Handle chat messages"""
    handle_chat_message(socketio, json)

if __name__ == '__main__':
    # Initialize login database with timeout handling
    print("Initializing database...")
    try:
        init_database()
        print("[OK] Database initialized successfully")
    except Exception as e:
        print(f"[WARNING] Database initialization failed: {e}")
        print("Continuing without database initialization...")
    
    # Use mkcert certificates for HTTPS
    cert_file = 'login/localhost+1.pem'
    key_file = 'login/localhost+1-key.pem'
    
    # For now, let's use HTTP to debug the connection issues
    print("* Starting application in HTTP mode for debugging...")
    print("* Application starting at: http://127.0.0.1:5000")
    
    try:
        socketio.run(app, host='127.0.0.1', port=5000, debug=True)
    except Exception as e:
        print(f"X Failed to start server: {e}")
        import traceback
        traceback.print_exc()