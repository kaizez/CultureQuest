from flask import Blueprint, render_template, request, session
from db_handler import fetch_challenges, check_and_update_rate_limit  # Fetch function from db_handler.py
from auth_decorators import login_required  # Import authentication decorator
import math
from sqlalchemy import text
from response.db import db_session
import base64

# Create a Blueprint for the event page
event_bp = Blueprint('event', __name__, template_folder='templates')

@event_bp.route('/')
@login_required  # Require authentication for event viewing   Authorization Controls with Decorators
def event_page():
    # Check if the user has exceeded the rate limit before proceeding
    user_id = session.get('user_id')  # Get the user's ID from the session
    if user_id and not check_and_update_rate_limit(user_id):
        return "Too Many Requests", 429  # 429 Too Many Requests if rate limit is exceeded
    
    page = request.args.get('page', 1, type=int)
    per_page = 8  # 8 challenges per page (2x4 grid)
    
    # Fetch all approved challenges from the database
    challenges = fetch_challenges(status_filter='Approved')  # Only approved challenges
    
    if not challenges:
        return render_template('event.html', 
                             featured_challenge=None, 
                             challenges=[], 
                             pagination=None)
    
    # Always use the first challenge as featured
    featured_challenge = challenges[0]
    
    # Get challenges for pagination (excluding the featured one)
    other_challenges = challenges[1:] if len(challenges) > 1 else []
    
    # Calculate pagination
    total_challenges = len(other_challenges)
    total_pages = math.ceil(total_challenges / per_page) if total_challenges > 0 else 1
    
    # Get challenges for current page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    current_page_challenges = other_challenges[start_idx:end_idx]
    
    # Pagination info
    pagination = {
        'page': page,
        'per_page': per_page,
        'total': total_challenges,
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
        'prev_num': page - 1 if page > 1 else None,
        'next_num': page + 1 if page < total_pages else None
    }
    
    query_user_statuses = text("SELECT challenge_id, status FROM challenge_status WHERE user_id = :user_id")
    status_results = db_session.execute(query_user_statuses, {"user_id": user_id}).fetchall()
    challenge_statuses = {str(row.challenge_id): row.status for row in status_results}

    query_all_challenges = text("SELECT * FROM challenge_submissions")
    all_challenges_results = db_session.execute(query_all_challenges).fetchall()

    current_challenges = []
    done_challenges = []

    for challenge_row in all_challenges_results:
        challenge_dict = dict(challenge_row._mapping)

        if challenge_dict.get('media_data'):
            encoded_image = base64.b64encode(challenge_dict['media_data']).decode('utf-8')
            challenge_dict['encoded_image'] = encoded_image
        else:
            challenge_dict['encoded_image'] = None


        status = challenge_statuses.get(str(challenge_dict['id']))

        if status == 'ACCEPTED':
            current_challenges.append(challenge_dict)
        elif status == 'COMPLETED' or status == 'APPROVED' or status == 'REJECTED':
            done_challenges.append(challenge_dict)

    return render_template('event.html', 
                        featured_challenge=featured_challenge,
                        challenges=current_page_challenges,
                        pagination=pagination,
                        current_challenges=current_challenges,
                        done_challenges=done_challenges,)
