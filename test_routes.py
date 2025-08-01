#!/usr/bin/env python3
"""
Test script to check available routes and Google OAuth status
"""

import os
from dotenv import load_dotenv

def test_routes():
    print("Testing CultureQuest Routes and OAuth Status")
    print("=" * 50)
    
    # Load environment variables
    load_dotenv()
    
    # Import app after loading env vars
    from app import app
    
    print("\nAvailable Routes:")
    with app.app_context():
        for rule in app.url_map.iter_rules():
            methods = ', '.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
            print(f"   {rule.rule:<30} [{methods}]")
    
    print(f"\nConfiguration Status:")
    print(f"   GOOGLE_OAUTH_ENABLED: {app.config.get('GOOGLE_OAUTH_ENABLED', False)}")
    print(f"   GOOGLE_CLIENT_ID: {'SET' if os.getenv('GOOGLE_CLIENT_ID') else 'NOT SET'}")
    print(f"   GOOGLE_CLIENT_SECRET: {'SET' if os.getenv('GOOGLE_CLIENT_SECRET') else 'NOT SET'}")
    
    # Check if /auth/google route exists
    google_route_exists = any(rule.rule == '/auth/google' for rule in app.url_map.iter_rules())
    print(f"   /auth/google route: {'EXISTS' if google_route_exists else 'MISSING'}")
    
    if google_route_exists:
        print("\nGoogle OAuth route is available")
    else:
        print("\nGoogle OAuth route not found - check configuration")
    
    # Test what happens when we access /auth/google
    print(f"\nTesting /auth/google endpoint:")
    try:
        with app.test_client() as client:
            response = client.get('/auth/google', follow_redirects=False)
            print(f"   Status Code: {response.status_code}")
            print(f"   Response Type: {response.content_type}")
            if 'Location' in response.headers:
                print(f"   Redirect To: {response.headers['Location']}")
            
            if response.status_code == 302:
                if 'accounts.google.com' in response.headers.get('Location', ''):
                    print("   SUCCESS: Redirecting to Google OAuth - Working!")
                elif '/login' in response.headers.get('Location', ''):
                    print("   ISSUE: Redirecting to login - OAuth not configured")
                else:
                    print(f"   UNKNOWN: Unexpected redirect: {response.headers.get('Location', 'None')}")
            elif response.status_code == 200:
                print("   ISSUE: Returning 200 - might be error page")
            else:
                print(f"   ERROR: Unexpected status code: {response.status_code}")
                
    except Exception as e:
        print(f"   ERROR: Error testing route: {e}")

if __name__ == "__main__":
    test_routes()