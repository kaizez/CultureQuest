from flask import Blueprint, render_template, request, session, redirect
from db_handler import fetch_challenges, check_and_update_rate_limit  # Fetch function from db_handler.py
import math
from functools import wraps

# Create a Blueprint for the event page
event_bp = Blueprint('event', __name__, template_folder='templates')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or 'email' not in session:
            # Redirect to login page if not authenticated
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@event_bp.route('/')
@login_required
def event_page():
    # Check if the user has exceeded the rate limit before proceeding
    email = session.get('email')  # Get the user's email from the session
    if email and not check_and_update_rate_limit(email):
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
    
    return render_template('event.html', 
                         featured_challenge=featured_challenge,
                         challenges=current_page_challenges,
                         pagination=pagination)