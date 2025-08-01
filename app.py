from flask import Flask
import os
import uuid
import pymysql
from dotenv import load_dotenv
from login import login_bp, google_bp, init_database

# Load environment variables
load_dotenv()

# Initialize the Flask app
app = Flask(__name__, template_folder='public')
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production-' + str(uuid.uuid4()))

# Configure OAuth settings
app.config['OAUTHLIB_INSECURE_TRANSPORT'] = os.environ.get('OAUTHLIB_INSECURE_TRANSPORT', 'False').lower() == 'true'
app.config['OAUTHLIB_RELAX_TOKEN_SCOPE'] = True

# Force HTTPS and correct hostname for OAuth redirects
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SERVER_NAME'] = os.environ.get('OAUTH_HOSTNAME', '127.0.0.1:5000')

# Register blueprints
app.register_blueprint(login_bp)

# Register Google blueprint if it was created (i.e., if credentials are available)
if google_bp is not None:
    app.register_blueprint(google_bp, url_prefix='/auth')
    app.config['GOOGLE_OAUTH_ENABLED'] = True
else:
    app.config['GOOGLE_OAUTH_ENABLED'] = False

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Use mkcert certificates
    cert_file = 'localhost+1.pem'
    key_file = 'localhost+1-key.pem'
    
    # Check if mkcert certificates exist
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("❌ mkcert certificates not found!")
        print("💡 Run these commands:")
        print("   mkcert -install")
        print("   mkcert localhost 127.0.0.1")
        print("   Then restart the app")
        exit(1)
    
    print("✅ mkcert SSL certificates found") 
    print("🚀 Application starting at: https://127.0.0.1:5000")
    print("🔒 HTTPS connection secured with mkcert certificates")
    
    try:
        # Use 127.0.0.1 instead of localhost for better compatibility
        app.run(debug=True, ssl_context=(cert_file, key_file), host='127.0.0.1', port=5000, threaded=True)
    except Exception as e:
        print(f"❌ Failed to start server: {e}")
        print("💡 Try deleting the .pem files and restart to regenerate certificates")