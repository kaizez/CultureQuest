import os
from flask import Flask, render_template
from flask_socketio import SocketIO
from challenge import challenge_bp
from admin_screening import admin_screening_bp
from event import event_bp
from chat import chat_bp, handle_join, handle_leave, handle_chat_message
from chat_manage import chat_manage_bp
from rewards import rewards_bp
from models import db, ChatRoom, RewardItem, UserPoints
import challenge_models
from dotenv import load_dotenv

def load_env():
    """Load environment variables from .env file."""
    basedir = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(basedir, '.env')
    if os.path.exists(dotenv_path):
        print(f"Loading .env file from {dotenv_path}")
        load_dotenv(dotenv_path)
        
        # Debug: Check if API key is loaded
        api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if api_key:
            print(f"[OK] VirusTotal API key loaded (length: {len(api_key)})")
        else:
            print("[ERROR] VirusTotal API key not found in environment")
    else:
        print("Warning: .env file not found.")
        print(f"Looking for .env at: {dotenv_path}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Files in directory: {os.listdir('.')}")

# Load environment variables
load_env()

# Initialize the Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-long-and-random-secret-key')

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

# Create tables if not exist and seed default chat rooms and rewards
with app.app_context():
    db.create_all()
    print("[OK] Database tables created/verified")
    
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

# Register Blueprints
app.register_blueprint(challenge_bp, url_prefix='/host')
app.register_blueprint(admin_screening_bp, url_prefix='/admin')
app.register_blueprint(event_bp, url_prefix='/event')
app.register_blueprint(chat_bp)
app.register_blueprint(chat_manage_bp)
app.register_blueprint(rewards_bp)

# SocketIO event handlers
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

@app.route('/')
def landing_page():
    return render_template('landing_page.html')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)