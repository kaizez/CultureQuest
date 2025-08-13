#!/usr/bin/env python3
"""
Generate SSL certificates for local development with 0.0.0.0 and localhost
"""

import os
import subprocess
import sys
from datetime import datetime, timedelta

def generate_openssl_cert():
    """Generate SSL certificate using OpenSSL"""
    try:
        # Check if openssl is available
        result = subprocess.run(['openssl', 'version'], capture_output=True, text=True)
        if result.returncode != 0:
            print("OpenSSL not found. Please install OpenSSL.")
            return False
        
        print("Generating SSL certificate with OpenSSL...")
        
        # Create a config file for Subject Alternative Names
        config_content = """[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Development
L = Local
O = CultureQuest
CN = 0.0.0.0

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = 0.0.0.0
IP.1 = 0.0.0.0
"""
        
        with open('ssl_config.conf', 'w') as f:
            f.write(config_content)
        
        # Generate private key
        subprocess.run([
            'openssl', 'genrsa', '-out', 'localhost-key.pem', '2048'
        ], check=True)
        
        # Generate certificate
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-key', 'localhost-key.pem',
            '-out', 'localhost.pem', '-days', '365', '-config', 'ssl_config.conf',
            '-extensions', 'v3_req'
        ], check=True)
        
        # Clean up config file
        os.remove('ssl_config.conf')
        
        print("✅ SSL certificates generated successfully!")
        print("Files created: localhost.pem, localhost-key.pem")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"Error generating certificate: {e}")
        return False
    except FileNotFoundError:
        print("OpenSSL not found. Please install OpenSSL first.")
        return False

def generate_python_cert():
    """Generate SSL certificate using Python's built-in capabilities"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import ipaddress
        
        print("Generating SSL certificate with Python cryptography...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Development"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CultureQuest"),
            x509.NameAttribute(NameOID.COMMON_NAME, "0.0.0.0"),
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
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("0.0.0.0"),
                x509.IPAddress(ipaddress.IPv4Address("0.0.0.0")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write private key
        with open("localhost-key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Write certificate
        with open("localhost.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        print("✅ SSL certificates generated successfully!")
        print("Files created: localhost.pem, localhost-key.pem")
        return True
        
    except ImportError:
        print("Python cryptography library not found.")
        print("Install it with: pip install cryptography")
        return False
    except Exception as e:
        print(f"Error generating certificate: {e}")
        return False

def main():
    print("🔐 SSL Certificate Generator for CultureQuest")
    print("=" * 50)
    
    # Check if certificates already exist
    if os.path.exists('localhost.pem') and os.path.exists('localhost-key.pem'):
        response = input("SSL certificates already exist. Regenerate? (y/N): ")
        if response.lower() != 'y':
            print("Keeping existing certificates.")
            return
        
        # Backup existing certificates
        import shutil
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        shutil.move('localhost.pem', f'localhost.pem.backup_{timestamp}')
        shutil.move('localhost-key.pem', f'localhost-key.pem.backup_{timestamp}')
        print(f"Backed up existing certificates with timestamp {timestamp}")
    
    # Try Python cryptography first, fallback to OpenSSL
    if not generate_python_cert():
        print("\nTrying OpenSSL method...")
        if not generate_openssl_cert():
            print("\n❌ Failed to generate SSL certificates.")
            print("Please install either:")
            print("1. Python cryptography: pip install cryptography")
            print("2. OpenSSL: https://slproweb.com/products/Win32OpenSSL.html")
            sys.exit(1)
    
    print("\n✅ SSL certificates ready!")
    print("You can now run the application with HTTPS support.")
    print("Access your app at: https://0.0.0.0:5000")
    print("\nNote: Your browser may show a security warning for self-signed certificates.")
    print("Click 'Advanced' and 'Proceed to 0.0.0.0' to continue.")

if __name__ == "__main__":
    main()