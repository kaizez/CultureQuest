import os
from flask import Flask, render_template
from dotenv import load_dotenv
from challenge import challenge_bp
from admin_screening import admin_screening_bp
from event import event_bp
from challenge_models import db

def load_env():
    """Load environment variables from .env file."""
    basedir = os.path.abspath(os.path.dirname(__file__))
    # Look for .env file in parent directory (main app directory)
    dotenv_path = os.path.join(os.path.dirname(basedir), '.env')
    if os.path.exists(dotenv_path):
        print(f"Loading .env file from {dotenv_path}")
        load_dotenv(dotenv_path)
    else:
        print("Warning: .env file not found.")
        print(f"Looking for .env at: {dotenv_path}")

# Load environment variables
load_env()

# Initialize the Flask app
app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key')

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

# Create tables if not exist
with app.app_context():
    db.create_all()
    print("[OK] Challenge database tables created/verified")

# Register Blueprints
app.register_blueprint(challenge_bp, url_prefix='/host')
app.register_blueprint(admin_screening_bp, url_prefix='/admin')
app.register_blueprint(event_bp, url_prefix='/event')

@app.route('/')
def landing_page():
    return render_template('landing_page.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
