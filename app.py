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
    
    # Generate SSL certificates if they don't exist
    cert_file = 'localhost.pem'
    key_file = 'localhost-key.pem'
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        # Generate self-signed certificate
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"CultureQuest"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate and key files
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    
    print("Application starting at: https://127.0.0.1:5000")
    
    try:
        # Use 127.0.0.1 instead of localhost for better compatibility
        app.run(debug=True, ssl_context=(cert_file, key_file), host='127.0.0.1', port=5000, threaded=True)
    except Exception as e:
        print(f"Failed to start server: {e}")