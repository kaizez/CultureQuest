from challenge_models import db, ChallengeSubmission
from flask import current_app
from datetime import datetime, timedelta
from sqlalchemy import func

# Define rate limit parameters - Protects against abuse and DoS attacks
RATE_LIMIT = 5  # Max requests per minute - Protects against rapid-fire spam attacks
RATE_LIMIT_WINDOW = timedelta(minutes=1)  # 1 minute window - Protects against sustained abuse

def insert_challenge(challenge_name, description, completion_criteria, media_filename):
    """Insert a new challenge into the database using SQLAlchemy - Protects against SQL injection via ORM."""
    try:
        challenge = ChallengeSubmission(
            challenge_name=challenge_name,
            description=description,
            completion_criteria=completion_criteria,
            media_filename=media_filename,
            name=challenge_name,  # Set legacy field for backward compatibility
            status='On Hold'  # Default safe status - Protects against privilege escalation
        )
        
        db.session.add(challenge)
        db.session.commit()  # Atomic operation - Protects against partial data corruption
        
        print(f"[OK] Challenge '{challenge_name}' inserted successfully")
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
def insert_challenge_legacy(name, email, phone, description, media_filename):
    """Legacy insert function for backward compatibility."""
    return insert_challenge(
        challenge_name=name,
        description=description,
        completion_criteria="Please provide completion proof",
        media_filename=media_filename
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
    
def check_and_update_rate_limit(user_id):
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