#!/usr/bin/env python3
"""
SSL Certificate Regeneration Script for CultureQuest
This script regenerates self-signed SSL certificates for local development.
"""

import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import datetime

def regenerate_ssl_certificates():
    """Regenerate SSL certificates for localhost"""
    
    cert_file = 'localhost.pem'
    key_file = 'localhost-key.pem'
    
    print("🔄 Regenerating SSL certificates...")
    
    # Remove existing certificates
    for file in [cert_file, key_file]:
        if os.path.exists(file):
            os.remove(file)
            print(f"🗑️  Removed existing {file}")
    
    try:
        # Generate private key
        print("🔑 Generating private key...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Generate certificate
        print("📜 Generating certificate...")
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
                x509.DNSName(u"127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate file
        print("💾 Writing certificate file...")
        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Write private key file
        print("💾 Writing private key file...")
        with open(key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print("✅ SSL certificates generated successfully!")
        print(f"📁 Certificate: {cert_file}")
        print(f"🔐 Private Key: {key_file}")
        print("🚀 You can now start your application with HTTPS")
        
    except Exception as e:
        print(f"❌ Error generating certificates: {e}")
        return False
    
    return True

if __name__ == "__main__":
    print("🔒 CultureQuest SSL Certificate Generator")
    print("=" * 50)
    
    success = regenerate_ssl_certificates()
    
    if success:
        print("\n🎉 Certificate generation completed!")
        print("💡 Now run: python app.py")
    else:
        print("\n💥 Certificate generation failed!")
        print("🔧 Please check your Python cryptography installation")