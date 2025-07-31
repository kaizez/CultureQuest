#!/usr/bin/env python3
"""
Test MySQL connection and create tables
"""
import os
import sys
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the current directory to Python path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db
from models import ChatRoom, Message, SecurityViolation, MutedUser

def test_connection():
    """Test the MySQL connection and create tables"""
    print("Testing MySQL connection...")
    
    with app.app_context():
        try:
            # Test connection
            db.engine.execute("SELECT 1")
            print("[OK] MySQL connection successful!")
            
            # Create all tables
            print("Creating database tables...")
            db.create_all()
            print("[OK] All tables created successfully!")
            
            # Create default chat rooms if they don't exist
            if ChatRoom.query.count() == 0:
                print("Creating default chat rooms...")
                default_rooms = [
                    ChatRoom(name="General Chat", description="Welcome to the general discussion room"),
                    ChatRoom(name="Tech Talk", description="Discuss technology, programming, and innovation"),
                    ChatRoom(name="Random", description="Talk about anything and everything"),
                    ChatRoom(name="File Sharing", description="Share and discuss files securely")
                ]
                
                for room in default_rooms:
                    db.session.add(room)
                db.session.commit()
                print("[OK] Default chat rooms created!")
            else:
                print("[INFO] Chat rooms already exist")
                
            # Test basic operations
            print("\nTesting basic database operations...")
            
            # Count records in each table
            room_count = ChatRoom.query.count()
            message_count = Message.query.count()
            violation_count = SecurityViolation.query.count()
            muted_count = MutedUser.query.count()
            
            print(f"[STATS] Database statistics:")
            print(f"  - Chat Rooms: {room_count}")
            print(f"  - Messages: {message_count}")
            print(f"  - Security Violations: {violation_count}")
            print(f"  - Muted Users: {muted_count}")
            
            print("\n[SUCCESS] MySQL migration completed successfully!")
            return True
            
        except Exception as e:
            print(f"[ERROR] Error: {str(e)}")
            return False

if __name__ == "__main__":
    success = test_connection()
    if not success:
        sys.exit(1)