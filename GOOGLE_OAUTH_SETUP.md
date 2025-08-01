# Google OAuth Setup Guide

## Prerequisites
1. SSL certificates (localhost.pem and localhost-key.pem) for HTTPS
2. Google Cloud Console project with OAuth 2.0 configured

## Step 1: Google Cloud Console Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing project
3. Enable the Google+ API (or Google People API)
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Configure the OAuth consent screen first if prompted
6. Create OAuth 2.0 Client ID:
   - Application type: Web application
   - Name: CultureQuest (or your preferred name)
   - Authorized redirect URIs: Add **exactly** this URL:
     ```
     https://127.0.0.1:5000/auth/google/authorized
     ```

## Step 2: Environment Variables

1. Copy `.env.example` to `.env`
2. Fill in the Google OAuth credentials:
   ```env
   GOOGLE_CLIENT_ID=your-actual-client-id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your-actual-client-secret
   GOOGLE_OAUTH_REDIRECT_URI=https://127.0.0.1:5000/auth/google/authorized
   OAUTH_HOSTNAME=127.0.0.1:5000
   ```

## Step 3: SSL Certificates

### Easy SSL Certificate Generation:
Run the included SSL certificate generator:
```bash
python generate_ssl_cert.py
```

This script will:
- Check if certificates already exist
- Generate new certificates with proper Subject Alternative Names for both `127.0.0.1` and `localhost`
- Handle backup of existing certificates
- Try multiple methods (Python cryptography or OpenSSL)

### Manual SSL Certificate Generation:
If the script doesn't work, you can generate certificates manually:

#### Using OpenSSL:
```bash
# Create config file for SAN (Subject Alternative Names)
cat > ssl_config.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Development
L = Local
O = CultureQuest
CN = 127.0.0.1

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = 127.0.0.1
IP.1 = 127.0.0.1
EOF

# Generate private key and certificate
openssl genrsa -out localhost-key.pem 2048
openssl req -new -x509 -key localhost-key.pem -out localhost.pem -days 365 -config ssl_config.conf -extensions v3_req
```

#### Or use mkcert (recommended):
```bash
# Install mkcert
# Windows: choco install mkcert
# macOS: brew install mkcert
# Linux: Check mkcert documentation

# Install local CA
mkcert -install

# Generate certificates
mkcert localhost 127.0.0.1 ::1
```

## Step 4: Running the Application

1. Make sure your `.env` file is configured
2. Run the application:
   ```bash
   python app.py
   ```
3. Access via HTTPS: `https://127.0.0.1:5000`

## Troubleshooting

### Error: "redirect_uri_mismatch"
- Ensure the redirect URI in Google Cloud Console exactly matches: `https://127.0.0.1:5000/auth/google/authorized`
- Check that you're accessing the app via `https://127.0.0.1:5000` (not http or localhost)

### Error: "This app doesn't comply with Google's OAuth 2.0 policy"
- Verify the redirect URI is registered in Google Cloud Console
- Ensure OAuth consent screen is configured
- Check that the Google+ API or People API is enabled

### SSL Certificate Issues
- Make sure both `localhost.pem` and `localhost-key.pem` exist
- Regenerate certificates if they're expired: `python generate_ssl_cert.py`
- Add security exception in your browser if prompted

### SSL Handshake Errors (Bad request version errors)
If you see errors like `code 400, message Bad request version` with garbled text:
1. This indicates SSL/TLS handshake problems
2. Your certificates might not be valid for `127.0.0.1`
3. **Solution**: Regenerate certificates with proper Subject Alternative Names:
   ```bash
   python generate_ssl_cert.py
   ```
4. Restart the application after regenerating certificates
5. Access via `https://127.0.0.1:5000` (not `localhost` or `http`)

### Development vs Production
- For local development: Use `https://127.0.0.1:5000`
- For production: Update redirect URI to your production domain
- Never set `OAUTHLIB_INSECURE_TRANSPORT=true` in production

## Security Notes
- Always use HTTPS for OAuth flows
- Keep your client secret secure and never commit it to version control
- The redirect URI must be exactly as registered in Google Cloud Console
- Use secure, randomly generated SECRET_KEY in production