#!/usr/bin/env python3
"""
Clear Challenge Database Script
===============================
This script safely clears ONLY the challenge-specific tables from the remote MySQL database.
It will NOT affect the main application's tables (chat_room, message, uploaded_file, etc.)

Tables that will be cleared:
- challenge_submissions

IMPORTANT: This action is irreversible. Make sure you have a backup if needed.
"""

import os
import sys
from dotenv import load_dotenv
from challenge_models import db, ChallengeSubmission
from db_handler import RateLimit
from flask import Flask

def load_env():
    """Load environment variables from .env file."""
    basedir = os.getcwd()
    # Look for .env file in parent directory (main app directory)
    dotenv_path = os.path.join(basedir, '.env')
    if os.path.exists(dotenv_path):
        print(f"Loading .env file from {dotenv_path}")
        load_dotenv(dotenv_path)
        return True
    else:
        print("ERROR: .env file not found.")
        print(f"Looking for .env at: {dotenv_path}")
        return False

def setup_app():
    """Setup Flask app with database configuration."""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'temp_key')
    
    # Build database URI from individual environment variables
    db_host = os.environ.get('DB_HOST')
    db_port = os.environ.get('DB_PORT')
    db_user = os.environ.get('DB_USER')
    db_password = os.environ.get('DB_PASSWORD')
    db_name = os.environ.get('DB_NAME')
    
    if not all([db_host, db_port, db_user, db_password, db_name]):
        print("ERROR: Database environment variables not found.")
        print("Required variables: DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME")
        return None, None
    
    app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    db.init_app(app)
    
    print(f"Connected to MySQL database: {db_host}:{db_port}/{db_name}")
    return app, f"{db_host}:{db_port}/{db_name}"

def confirm_action(db_info):
    """Ask for user confirmation before clearing data."""
    print("\n" + "="*60)
    print("⚠️  DATABASE CLEAR OPERATION ⚠️")
    print("="*60)
    print(f"Database: {db_info}")
    print("Tables to be cleared:")
    print("  - challenge_submissions (ALL challenge data will be deleted)")
    print("\nTables that will NOT be affected:")
    print("  - chat_room, message, uploaded_file, security_violation, muted_user")
    print("  - Any other main application tables")
    print("\n⚠️  This action is IRREVERSIBLE!")
    print("="*60)
    
    # Ask for confirmation
    response = input("\nType 'CLEAR CHALLENGES' to confirm (anything else to cancel): ")
    return response == 'CLEAR CHALLENGES'

def clear_challenge_tables():
    """Clear only the challenge-specific tables."""
    try:
        # Get count before deletion for reporting
        initial_count = ChallengeSubmission.query.count()
        print(f"\nFound {initial_count} challenge records to delete...")
        
        if initial_count == 0:
            print("✅ No challenge data found. Nothing to clear.")
            return True
        
        # Delete all challenge submissions
        deleted_challenges = db.session.query(ChallengeSubmission).delete()
        
        # Commit the changes
        db.session.commit()
        
        print(f"✅ Successfully deleted {deleted_challenges} challenge records")
        print("✅ Challenge database cleared successfully!")
        
        # Verify the deletion
        remaining_count = ChallengeSubmission.query.count()
        if remaining_count == 0:
            print("✅ Verification: No challenge records remaining")
        else:
            print(f"⚠️  Warning: {remaining_count} records still remain")
            
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"❌ ERROR: Failed to clear challenge database: {str(e)}")
        return False

def main():
    """Main function to orchestrate the database clearing process."""
    print("Challenge Database Clear Script")
    print("===============================")
    
    # Load environment variables
    if not load_env():
        print("❌ Cannot proceed without environment variables")
        sys.exit(1)
    
    # Setup Flask app and database connection
    app, db_info = setup_app()
    if not app:
        print("❌ Cannot proceed without database connection")
        sys.exit(1)
    
    # Get user confirmation
    if not confirm_action(db_info):
        print("❌ Operation cancelled by user")
        sys.exit(0)
    
    # Perform the clearing operation
    with app.app_context():
        print("\n🔄 Starting database clear operation...")
        
        if clear_challenge_tables():
            print("\n🎉 Database clear operation completed successfully!")
            print("   Only challenge-specific tables were affected.")
            print("   Main application data remains intact.")
        else:
            print("\n❌ Database clear operation failed!")
            sys.exit(1)

if __name__ == '__main__':
    main()