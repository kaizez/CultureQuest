from models import db
from challenge_models import ChallengeSubmission
from flask import current_app
from datetime import datetime

def insert_challenge(challenge_name, description, completion_criteria, media_filename):
    """Insert a new challenge into the database using SQLAlchemy."""
    try:
        challenge = ChallengeSubmission(
            challenge_name=challenge_name,
            description=description,
            completion_criteria=completion_criteria,
            media_filename=media_filename,
            name=challenge_name,  # Set legacy field for backward compatibility
            status='On Hold'
        )
        
        db.session.add(challenge)
        db.session.commit()
        
        print(f"[OK] Challenge '{challenge_name}' inserted successfully")
        return challenge.id
        
    except Exception as e:
        db.session.rollback()
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