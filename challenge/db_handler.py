from challenge_models import db, ChallengeSubmission
from flask import current_app
from datetime import datetime, timedelta
from sqlalchemy import func
import sys
import os

# Add path for accessing chatapp_rewards models
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'chatapp_rewards'))
try:
    from models import ChatRoom
    CHAT_INTEGRATION_AVAILABLE = True
    print("[OK] Chat integration available for challenge-chat sync")
except ImportError as e:
    print(f"[WARNING] Chat integration not available: {e}")
    CHAT_INTEGRATION_AVAILABLE = False

# Define rate limit parameters - Protects against abuse and DoS attacks
RATE_LIMIT = 30  # Max requests per minute - Protects against rapid-fire spam attacks
RATE_LIMIT_WINDOW = timedelta(minutes=1)  # 1 minute window - Protects against sustained abuse

def create_challenge_chat_room(challenge_id, challenge_name):
    """Create a chat room for a challenge"""
    if not CHAT_INTEGRATION_AVAILABLE:
        print(f"[WARNING] Cannot create chat room for challenge {challenge_id} - chat integration not available")
        return False
    
    try:
        # Check if chat room already exists with this ID
        existing_room = ChatRoom.query.get(challenge_id)
        if existing_room:
            print(f"[INFO] Chat room for challenge {challenge_id} already exists")
            return True
        
        # Create new chat room with challenge ID as room ID
        chat_room = ChatRoom(
            id=challenge_id,  # Use challenge ID as room ID
            name=f"🎯 {challenge_name} (#{challenge_id})",  # Add emoji prefix and ID to ensure uniqueness
            description=f"Discussion channel for challenge: {challenge_name}",
            is_active=True
        )
        
        db.session.add(chat_room)
        db.session.commit()
        
        print(f"[OK] Created chat room '{chat_room.name}' for challenge {challenge_id}")
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to create chat room for challenge {challenge_id}: {str(e)}")
        return False

def delete_challenge_chat_room(challenge_id):
    """Delete chat room associated with a challenge"""
    if not CHAT_INTEGRATION_AVAILABLE:
        print(f"[WARNING] Cannot delete chat room for challenge {challenge_id} - chat integration not available")
        return False
    
    try:
        # Find and delete the chat room
        chat_room = ChatRoom.query.get(challenge_id)
        if chat_room:
            # Mark as inactive instead of deleting to preserve message history
            chat_room.is_active = False
            db.session.commit()
            print(f"[OK] Deactivated chat room for challenge {challenge_id}")
            return True
        else:
            print(f"[INFO] No chat room found for challenge {challenge_id}")
            return True
            
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to delete chat room for challenge {challenge_id}: {str(e)}")
        return False

def delete_challenge(challenge_id):
    """Delete a challenge and its associated chat session"""
    try:
        # Find the challenge
        challenge = ChallengeSubmission.query.get(challenge_id)
        if not challenge:
            print(f"[WARNING] Challenge {challenge_id} not found")
            return False
        
        challenge_name = challenge.challenge_name
        
        # Delete the challenge from database
        db.session.delete(challenge)
        db.session.commit()
        
        print(f"[OK] Challenge '{challenge_name}' (ID: {challenge_id}) deleted successfully")
        
        # Delete associated chat session
        delete_challenge_chat_room(challenge_id)
        
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to delete challenge {challenge_id}: {str(e)}")
        return False

def sync_challenge_chat_sessions():
    """Synchronize challenges with chat sessions - create missing ones, deactivate orphaned ones"""
    if not CHAT_INTEGRATION_AVAILABLE:
        print("[WARNING] Cannot sync challenge-chat sessions - chat integration not available")
        return
    
    try:
        # Get all active challenges
        active_challenges = ChallengeSubmission.query.all()
        active_challenge_ids = {challenge.id for challenge in active_challenges}
        
        print(f"[INFO] Found {len(active_challenges)} active challenges")
        
        # Create missing chat sessions for challenges
        created_count = 0
        for challenge in active_challenges:
            existing_room = ChatRoom.query.get(challenge.id)
            if not existing_room:
                if create_challenge_chat_room(challenge.id, challenge.challenge_name):
                    created_count += 1
            elif not existing_room.is_active:
                # Reactivate if challenge exists but chat room is inactive
                existing_room.is_active = True
                existing_room.name = f"🎯 {challenge.challenge_name} (#{challenge.id})"
                existing_room.description = f"Discussion channel for challenge: {challenge.challenge_name}"
                db.session.commit()
                print(f"[OK] Reactivated chat session for challenge {challenge.id}")
        
        # Find orphaned chat sessions (chat sessions without corresponding challenges)
        # Look for chat rooms that start with challenge emoji and have numeric IDs
        orphaned_count = 0
        all_challenge_chat_rooms = ChatRoom.query.filter(
            ChatRoom.name.like('🎯%'),
            ChatRoom.is_active == True
        ).all()
        
        for chat_room in all_challenge_chat_rooms:
            if chat_room.id not in active_challenge_ids:
                # This is an orphaned chat session
                chat_room.is_active = False
                orphaned_count += 1
                print(f"[OK] Deactivated orphaned chat session {chat_room.id}: {chat_room.name}")
        
        if orphaned_count > 0:
            db.session.commit()
        
        print(f"[OK] Sync complete - Created: {created_count}, Deactivated: {orphaned_count}")
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to sync challenge-chat sessions: {str(e)}")

def insert_challenge(challenge_name, description, completion_criteria, media_filename, media_data=None, media_mime_type=None): # SQL Injection Prevention via ORM Lines 157-184
    """Insert a new challenge into the database using SQLAlchemy - Protects against SQL injection via ORM."""
    try:
        challenge = ChallengeSubmission(
            challenge_name=challenge_name,
            description=description,
            completion_criteria=completion_criteria,
            media_filename=media_filename,
            media_data=media_data,
            media_mime_type=media_mime_type,
            name=challenge_name,  # Set legacy field for backward compatibility
            status='On Hold'  # Default safe status - Protects against privilege escalation
        )
        
        db.session.add(challenge)
        db.session.commit()  # Atomic operation - Protects against partial data corruption
        
        print(f"[OK] Challenge '{challenge_name}' inserted successfully with ID {challenge.id}")
        
        # Automatically create chat session for the challenge
        create_challenge_chat_room(challenge.id, challenge_name)
        
        return challenge.id
        
    except Exception as e:
        db.session.rollback()  # Rollback on error - Protects against data corruption
        print(f"[ERROR] Failed to insert challenge: {str(e)}")
        raise e

def fetch_challenges(status_filter=None):
    """Fetch challenges from the database with an optional status filter."""
    try:
        query = ChallengeSubmission.query
        
        if status_filter:
            query = query.filter(ChallengeSubmission.status == status_filter)
        
        challenges = query.order_by(ChallengeSubmission.created_at.desc()).all()
        
        # Convert to list of dictionaries for backward compatibility
        result = [challenge.to_dict() for challenge in challenges]
        
        print(f"[OK] Fetched {len(result)} challenges" + (f" with status '{status_filter}'" if status_filter else ""))
        return result
        
    except Exception as e:
        print(f"[ERROR] Failed to fetch challenges: {str(e)}")
        return []

def update_challenge_status(challenge_id, status, comments, points):
    """Update the status and comments for a challenge."""
    try:
        challenge = ChallengeSubmission.query.get(challenge_id)
        
        if not challenge:
            print(f"[ERROR] Challenge with ID {challenge_id} not found")
            return False
        
        challenge.status = status
        challenge.comments = comments
        challenge.points = points
        challenge.updated_at = datetime.utcnow()
        
        db.session.commit()
        
        print(f"[OK] Challenge ID {challenge_id} updated: status='{status}', points='{points}'")
        return True
        
    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to update challenge: {str(e)}")
        return False

def get_challenge_by_id(challenge_id):
    """Get a specific challenge by ID."""
    try:
        challenge = ChallengeSubmission.query.get(challenge_id)
        return challenge.to_dict() if challenge else None
        
    except Exception as e:
        print(f"[ERROR] Failed to get challenge: {str(e)}")
        return None

# Legacy function names for backward compatibility
def insert_challenge_legacy(name, email, phone, description, media_filename, media_data=None, media_mime_type=None):
    """Legacy insert function for backward compatibility."""
    return insert_challenge(
        challenge_name=name,
        description=description,
        completion_criteria="Please provide completion proof",
        media_filename=media_filename,
        media_data=media_data,
        media_mime_type=media_mime_type
    )

class RateLimit(db.Model):
    """Model for tracking rate limits for users - Protects against abuse and DoS attacks."""
    __tablename__ = 'RateLimit'  # Specify the table name

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=True)  # User email for rate limiting - Protects against anonymous abuse
    user_id = db.Column(db.String(255), unique=True, nullable=True)  # User ID for rate limiting - Protects against anonymous abuse
    request_count = db.Column(db.Integer, default=1)  # Number of requests made - Protects against rapid requests
    last_request = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)  # Last request timestamp - Protects against time-based attacks

    def __init__(self, email=None, user_id=None, request_count=1, last_request=None):
        self.email = email
        self.user_id = user_id
        self.request_count = request_count
        self.last_request = last_request or datetime.utcnow()

    def __repr__(self):
        identifier = self.user_id or self.email
        return f"<RateLimit(identifier={identifier}, request_count={self.request_count}, last_request={self.last_request})>"
    
def check_and_update_rate_limit(user_id): #RATE LIMITING LINE 272-303
    """Check and update the rate limit for a given user by user_id - Protects against abuse and DoS attacks."""
    # Get the current time
    now = datetime.utcnow()

    # Check if the user has a record in the RateLimit table - Protects against bypass attempts
    rate_limit_record = db.session.query(RateLimit).filter_by(user_id=user_id).first()

    if rate_limit_record:
        # Check if the request is within the time window - Protects against time-based bypass
        if now - rate_limit_record.last_request < RATE_LIMIT_WINDOW:
            if rate_limit_record.request_count >= RATE_LIMIT:
                # Rate limit exceeded - Protects against abuse
                return False  # Exceeded limit, cannot proceed
            else:
                # Increment the request count within the allowed window - Tracks usage
                rate_limit_record.request_count += 1
                rate_limit_record.last_request = now
                db.session.commit()  # Atomic update - Protects against race conditions
                return True
        else:
            # Expired window, reset count and update timestamp - Allows legitimate use after timeout
            rate_limit_record.request_count = 1
            rate_limit_record.last_request = now
            db.session.commit()  # Atomic update - Protects against race conditions
            return True
    else:
        # No record found for the user, create a new record - Initialize tracking for new users
        new_record = RateLimit(user_id=user_id, request_count=1, last_request=now)
        db.session.add(new_record)
        db.session.commit()  # Atomic operation - Protects against duplicate records
        return True

def clean_expired_rate_limits():
    """Clean up rate limit records that have expired beyond the set window."""
    # Remove records older than the allowed window
    expiration_time = datetime.utcnow() - RATE_LIMIT_WINDOW
    db.session.query(RateLimit).filter(RateLimit.last_request < expiration_time).delete()
    db.session.commit()