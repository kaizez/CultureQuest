#!/usr/bin/env python3
"""
Quick setup script for Google OAuth configuration
"""

import os
import sys
from dotenv import load_dotenv

def main():
    print("Google OAuth Setup for CultureQuest")
    print("=" * 50)
    
    # Load existing .env if it exists
    if os.path.exists('.env'):
        load_dotenv()
        print("Found existing .env file")
    else:
        print("No .env file found, will create one")
    
    # Check current status
    current_client_id = os.getenv('GOOGLE_CLIENT_ID', '')
    current_client_secret = os.getenv('GOOGLE_CLIENT_SECRET', '')
    
    print(f"\nCurrent status:")
    print(f"GOOGLE_CLIENT_ID: {'SET' if current_client_id and current_client_id != 'your-google-client-id.apps.googleusercontent.com' else 'NOT SET'}")
    print(f"GOOGLE_CLIENT_SECRET: {'SET' if current_client_secret and current_client_secret != 'your-google-client-secret' else 'NOT SET'}")
    
    if current_client_id and current_client_secret and \
       current_client_id != 'your-google-client-id.apps.googleusercontent.com' and \
       current_client_secret != 'your-google-client-secret':
        print("\nGoogle OAuth appears to be configured!")
        print("If it's still not working, check:")
        print("1. Redirect URI in Google Cloud Console: https://0.0.0.0:5000/auth/google/authorized")
        print("2. OAuth consent screen is configured")
        print("3. Google+ API or People API is enabled")
        return
    
    print("\nGoogle OAuth is not properly configured")
    print("\nTo fix this, you need to:")
    print("\n1. Go to Google Cloud Console: https://console.cloud.google.com/")
    print("2. Create/select a project")
    print("3. Enable Google+ API or People API")
    print("4. Create OAuth 2.0 Client ID:")
    print("   - Application type: Web application")
    print("   - Authorized redirect URIs: https://0.0.0.0:5000/auth/google/authorized")
    print("5. Copy the Client ID and Client Secret")
    
    print("\nWould you like to configure them now?")
    response = input("Enter your credentials? (y/N): ")
    
    if response.lower() == 'y':
        print("\nEnter your Google OAuth credentials:")
        client_id = input("Google Client ID: ").strip()
        client_secret = input("Google Client Secret: ").strip()
        
        if client_id and client_secret:
            # Read existing .env content
            env_content = ""
            if os.path.exists('.env'):
                with open('.env', 'r') as f:
                    env_content = f.read()
            
            # Update or add Google OAuth settings
            lines = env_content.split('\n') if env_content else []
            
            # Remove existing Google OAuth lines
            lines = [line for line in lines if not line.startswith('GOOGLE_CLIENT_ID=') and not line.startswith('GOOGLE_CLIENT_SECRET=')]
            
            # Add new credentials
            lines.extend([
                f"GOOGLE_CLIENT_ID={client_id}",
                f"GOOGLE_CLIENT_SECRET={client_secret}",
                "GOOGLE_OAUTH_REDIRECT_URI=https://0.0.0.0:5000/auth/google/authorized",
                "OAUTH_HOSTNAME=0.0.0.0:5000"
            ])
            
            # Write back to .env
            with open('.env', 'w') as f:
                f.write('\n'.join(line for line in lines if line.strip()) + '\n')
            
            print("\nGoogle OAuth credentials saved to .env file!")
            print("Please restart the application for changes to take effect")
            print("Access your app at: https://0.0.0.0:5000")
        else:
            print("Invalid credentials provided")
    else:
        print("\nManual setup:")
        print("1. Edit the .env file")
        print("2. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET")
        print("3. Restart the application")

if __name__ == "__main__":
    main()