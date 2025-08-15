import os
import sys
import uuid
import pymysql
from flask import Flask, render_template, send_from_directory, abort, session, Response
from flask_socketio import SocketIO
from dotenv import load_dotenv
from jinja2 import FileSystemLoader, ChoiceLoader
from secure import Secure

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
try:
    from db_handler import RateLimit
    print("[OK] db_handler imported successfully")
    from challenge import challenge_bp
    print("[OK] challenge_bp imported successfully")
    from admin_screening import admin_screening_bp
    print("[OK] admin_screening_bp imported successfully")
    from event import event_bp
    print("[OK] event_bp imported successfully")
    from challenge_models import db
    print("[OK] challenge_models imported successfully")
except Exception as e:
    print(f"[ERROR] Challenge module import failed: {e}")
    import traceback
    traceback.print_exc()
    # Create a dummy blueprint to prevent app crash
    from flask import Blueprint
    challenge_bp = Blueprint('challenge_dummy', __name__)
    admin_screening_bp = Blueprint('admin_screening_dummy', __name__)
    event_bp = Blueprint('event_dummy', __name__)

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


# Import response module
os.chdir(os.path.join(current_dir, 'response'))
from response.response import response_bp
from response.mod import moderate_bp

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
    FileSystemLoader(os.path.join(current_dir, 'templates')),  # Root templates for error pages
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

# Force HTTPS for OAuth redirects
app.config['PREFERRED_URL_SCHEME'] = 'https'
# Remove SERVER_NAME to allow dynamic host binding

# RECAPTCHA Config
app.config['RECAPTCHA_SITE_KEY'] = os.environ.get('RECAPTCHA_SITE_KEY')
app.config['RECAPTCHA_SECRET_KEY'] = os.environ.get('RECAPTCHA_SECRET_KEY')

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

# Initialize security headers
secure_headers = Secure()

@app.after_request
def set_security_headers(response):
    """Add security headers to all responses"""
    secure_headers.framework.flask(response)
    return response

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
    
    # No default chat rooms needed - challenge rooms will be created automatically
    
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
app.register_blueprint(challenge_bp, url_prefix='/host')  # Keep /host for challenge routes
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
app.register_blueprint(moderate_bp, url_prefix='/moderate')

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
    """Serve uploaded files from database"""
    try:
        # Import here to avoid circular imports
        sys.path.insert(0, os.path.join(current_dir, 'challenge'))
        from challenge_models import ChallengeSubmission

        # Find challenge with this media filename
        challenge = ChallengeSubmission.query.filter_by(media_filename=filename).first()

        if challenge and challenge.media_data:
            # Serve from database
            return Response(
                challenge.media_data,
                mimetype=challenge.media_mime_type or 'application/octet-stream',
                headers={'Content-Disposition': f'inline; filename="{filename}"'}
            )
        else:
            # Fallback to filesystem (for backward compatibility)
            upload_path = os.path.join(current_dir, 'challenge/static/uploads')
            if os.path.exists(os.path.join(upload_path, filename)):
                return send_from_directory(upload_path, filename)
            abort(404)
    except Exception as e:
        print(f"Error serving file {filename}: {str(e)}")
        abort(404)


# Global Error Handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors globally"""
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors globally"""
    return render_template('500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors - redirect to 404 for security"""
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(error):
    """Handle any unhandled exceptions globally"""
    print(f"Unhandled exception: {error}")
    return render_template('500.html'), 500

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

# AI Chatbot API endpoint
@app.route('/api/chatbot', methods=['POST'])
def chatbot_api():
    """Handle chatbot requests with streaming"""
    try:
        from flask import request, Response, stream_template
        import requests
        import json
        
        data = request.get_json()
        user_message = data.get('message', '').strip()
        
        if not user_message:
            return {'error': 'No message provided'}, 400
        
        # Get Ollama URL from environment
        ollama_base_url = os.environ.get('OLLAMA_URL', 'http://localhost:11434')
        ollama_url = f"{ollama_base_url}/api/generate"
        
        def generate():
            try:
                payload = {
                    "model": "culturequest-faq",
                    "prompt": user_message,
                    "stream": True,
                    "keep_alive": "30m"
                }
                
                response = requests.post(ollama_url, json=payload, stream=True, timeout=30)
                
                if response.status_code == 200:
                    for line in response.iter_lines():
                        if line:
                            try:
                                chunk_data = json.loads(line.decode('utf-8'))
                                if 'response' in chunk_data:
                                    yield f"data: {json.dumps({'response': chunk_data['response']})}\n\n"
                                if chunk_data.get('done', False):
                                    yield f"data: {json.dumps({'done': True})}\n\n"
                                    break
                            except json.JSONDecodeError:
                                continue
                else:
                    yield f"data: {json.dumps({'error': 'Chatbot service unavailable'})}\n\n"
                    
            except requests.exceptions.RequestException as e:
                print(f"Ollama connection error: {e}")
                yield f"data: {json.dumps({'response': 'I apologize, but I am temporarily unavailable. Please try again later.'})}\n\n"
                yield f"data: {json.dumps({'done': True})}\n\n"
            except Exception as e:
                print(f"Chatbot API error: {e}")
                yield f"data: {json.dumps({'error': 'Internal server error'})}\n\n"
        
        return Response(generate(), mimetype='text/plain')
            
    except Exception as e:
        print(f"Chatbot API error: {e}")
        return {'error': 'Internal server error'}, 500

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
    
    # Check if certificate files exist
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("* Starting application in HTTPS mode...")
        print("* Application starting at: https://0.0.0.0:5000")
        
        try:
            socketio.run(app, host='0.0.0.0', port=5000, debug=True, 
                        ssl_context=(cert_file, key_file))
        except Exception as e:
            print(f"X Failed to start HTTPS server: {e}")
            print("* Falling back to HTTP mode...")
            socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    else:
        print("* Certificate files not found, starting in HTTP mode...")
        print(f"* Looking for: {cert_file} and {key_file}")
        print("* Application starting at: http://0.0.0.0:5000")
        
        try:
            socketio.run(app, host='0.0.0.0', port=5000, debug=True)
        except Exception as e:
            print(f"X Failed to start server: {e}")
            import traceback
            traceback.print_exc()