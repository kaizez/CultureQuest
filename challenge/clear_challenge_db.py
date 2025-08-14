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
from db_handler import RateLimit, delete_challenge_chat_room, CHAT_INTEGRATION_AVAILABLE
from flask import Flask

# Import chat models for cleanup
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'chatapp_rewards'))
try:
    from models import ChatRoom, SecurityViolation
    CHAT_CLEANUP_AVAILABLE = True
except ImportError:
    CHAT_CLEANUP_AVAILABLE = False

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
    print("  - security_violation (violations from challenge chat rooms)")
    print("\nTables that will NOT be affected:")
    print("  - chat_room, message, uploaded_file, muted_user")
    print("  - Any other main application tables")
    print("\n⚠️  This action is IRREVERSIBLE!")
    print("="*60)
    
    # Ask for confirmation
    response = input("\nType 'CLEAR CHALLENGES' to confirm (anything else to cancel): ")
    return response == 'CLEAR CHALLENGES'

def clear_challenge_tables():
    """Clear only the challenge-specific tables and associated chat sessions."""
    try:
        # Get count before deletion for reporting
        initial_count = ChallengeSubmission.query.count()
        print(f"\nFound {initial_count} challenge records to delete...")
        
        if initial_count == 0:
            print("✅ No challenge data found. Nothing to clear.")
            return True
        
        # Get all challenge IDs for chat session cleanup
        challenge_ids = [challenge.id for challenge in ChallengeSubmission.query.all()]
        
        # Delete all challenge submissions
        deleted_challenges = db.session.query(ChallengeSubmission).delete()
        
        # Commit the changes
        db.session.commit()
        
        print(f"✅ Successfully deleted {deleted_challenges} challenge records")
        
        # Clean up associated chat sessions and security violations
        if CHAT_CLEANUP_AVAILABLE and challenge_ids:
            print(f"🔄 Cleaning up {len(challenge_ids)} associated chat sessions and violations...")
            deactivated_count = 0
            violations_deleted = 0
            
            for challenge_id in challenge_ids:
                chat_room = ChatRoom.query.get(challenge_id)
                if chat_room and chat_room.is_active:
                    chat_room.is_active = False
                    deactivated_count += 1
                    print(f"   Deactivated chat session for challenge {challenge_id}")
                
                # Delete security violations for this challenge room using raw SQL to avoid model schema issues
                try:
                    violations_result = db.session.execute(db.text("SELECT COUNT(*) FROM security_violation WHERE room_id = :room_id"), {"room_id": challenge_id})
                    violations_count = violations_result.scalar()
                    
                    if violations_count > 0:
                        db.session.execute(db.text("DELETE FROM security_violation WHERE room_id = :room_id"), {"room_id": challenge_id})
                        violations_deleted += violations_count
                        print(f"   Deleted {violations_count} security violations for challenge {challenge_id}")
                except Exception as e:
                    print(f"   Warning: Could not delete violations for challenge {challenge_id}: {e}")
            
            if deactivated_count > 0 or violations_deleted > 0:
                db.session.commit()
                if deactivated_count > 0:
                    print(f"✅ Deactivated {deactivated_count} challenge chat sessions")
                if violations_deleted > 0:
                    print(f"✅ Deleted {violations_deleted} security violations from challenge rooms")
            else:
                print("✅ No active challenge chat sessions or violations found")
        elif not CHAT_CLEANUP_AVAILABLE:
            print("⚠️  Chat cleanup not available - chat sessions and violations may remain")
        
        print("✅ Challenge database cleared successfully!")
        
        # Verify the deletion
        remaining_count = ChallengeSubmission.query.count()
        if remaining_count == 0:
            print("✅ Verification: No challenge records remaining")
        else:
            print(f"⚠️  Warning: {remaining_count} records still remain")
        
        # Important: Sync chat sessions after clearing to ensure any new challenges have chat rooms
        if CHAT_INTEGRATION_AVAILABLE:
            print("🔄 Syncing challenge-chat sessions...")
            from db_handler import sync_challenge_chat_sessions
            sync_challenge_chat_sessions()
            
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