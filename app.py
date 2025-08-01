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
    print("Google OAuth configured and enabled")
    print("   Flask-Dance blueprint registered at /auth/google")
else:
    app.config['GOOGLE_OAUTH_ENABLED'] = False
    print("Google OAuth not configured - missing GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET")
    print("   Fallback route will be used instead")
    print("   Run: python setup_google_oauth.py to configure")

if __name__ == '__main__':
    print("Starting CultureQuest with Blueprint structure...")
    
    # Initialize database
    print("Initializing database...")
    if init_database():
        print("Database initialized successfully!")
    else:
        print("Warning: Database initialization failed. Check your database connection.")
    
    # Check if we have SSL certificates for HTTPS
    ssl_context = None
    cert_files = [
        ('localhost.pem', 'localhost-key.pem'),
        ('cert.pem', 'key.pem'),
        ('server.crt', 'server.key')
    ]
    
    for cert_file, key_file in cert_files:
        if os.path.exists(cert_file) and os.path.exists(key_file):
            try:
                # Test if we can create SSL context
                import ssl
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                context.load_cert_chain(cert_file, key_file)
                ssl_context = (cert_file, key_file)
                print(f"SSL certificates validated ({cert_file}, {key_file}) - starting with HTTPS")
                print("Application starting at: https://127.0.0.1:5000")
                print("Note: If you get certificate warnings in your browser, click 'Advanced' and 'Proceed to 127.0.0.1'")
                break
            except Exception as e:
                print(f"SSL certificate error with {cert_file}: {e}")
                continue
    
    if ssl_context is None:
        print("No valid SSL certificates found - starting with HTTP")
        print("Application starting at: http://127.0.0.1:5000")
        print("WARNING: Google OAuth requires HTTPS! Generate SSL certificates first.")
        
        # Set OAUTHLIB_INSECURE_TRANSPORT for HTTP development (not recommended)
        app.config['OAUTHLIB_INSECURE_TRANSPORT'] = True
        print("Enabled OAUTHLIB_INSECURE_TRANSPORT for HTTP development")
    
    try:
        # Use 127.0.0.1 instead of localhost for better compatibility
        app.run(debug=True, ssl_context=ssl_context, host='127.0.0.1', port=5000, threaded=True)
    except Exception as e:
        print(f"Failed to start server: {e}")
        if ssl_context:
            print("SSL Error - trying without SSL...")
            app.config['OAUTHLIB_INSECURE_TRANSPORT'] = True
            app.run(debug=True, host='127.0.0.1', port=5000, threaded=True)