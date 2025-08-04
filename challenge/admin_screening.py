from flask import Blueprint, render_template, request, redirect, url_for, session
from db_handler import fetch_challenges, update_challenge_status, check_and_update_rate_limit  # Import necessary functions
from input_sanitizer import validate_admin_input  # Protects against injection attacks in admin panel
from security_logger import log_authorization_failure, log_admin_action, log_rate_limit_exceeded  # Protects against unmonitored admin activity
from auth_decorators import admin_required, login_required  # Import centralized authentication decorators
from datetime import datetime
from challenge_models import db  # Import db session for secure database operations

# Create a Blueprint for the admin screening page
admin_screening_bp = Blueprint('admin_screening', __name__, template_folder='templates')

# Authentication decorators are now imported from auth_decorators.py

@admin_screening_bp.route('/', methods=['GET', 'POST'])
@admin_required  # Protects against non-admin users accessing admin functionality
def admin_page():
    # Check if the user has exceeded the rate limit before proceeding - Protects against spam/DoS attacks
    user_id = session.get('user_id')  # Get the user_id from the session
    if user_id and not check_and_update_rate_limit(user_id):
        log_rate_limit_exceeded(user_id)  # Log rate limit violation for monitoring
        return "Too Many Requests", 429  # 429 Too Many Requests if rate limit is exceeded - Protects against abuse

    # Fetch all unapproved challenges from the database
    challenges = fetch_challenges(status_filter='On Hold')  # Only unapproved challenges

    # Handle form submission for updating challenge status or comments
    if request.method == 'POST':
        # Sanitize and validate all admin input - Protects against injection attacks
        form_data = {
            'challenge_id': request.form.get('challenge_id'),
            'status': request.form.get('status'),
            'comments': request.form.get('comments'),
            'points': request.form.get('points')
        }
        
        sanitized_data = validate_admin_input(form_data)
        
        # Extract sanitized values - All input is now protected against injection
        challenge_id = sanitized_data.get('challenge_id')
        status = sanitized_data.get('status')
        comments = sanitized_data.get('comments', '')
        points = sanitized_data.get('points')
        
        # Additional validation - Protects against malformed requests
        if not challenge_id:
            return "Invalid challenge ID", 400

        # If a status is provided (Approve, Reject, or On Hold), update status and comments
        if status:
            log_admin_action('status_update', challenge_id, f'Status: {status}, Points: {points}')  # Log admin action for audit
            update_challenge_status(challenge_id, status, comments, points)
        else:
            # Use SQLAlchemy ORM to prevent SQL injection attacks
            from challenge_models import ChallengeSubmission
            challenge = ChallengeSubmission.query.get(challenge_id)
            if challenge:
                log_admin_action('comments_update', challenge_id, f'Comments updated, Points: {points}')  # Log admin action for audit
                challenge.comments = comments  # Protects against SQL injection via ORM parameterization
                challenge.points = points      # Protects against SQL injection via ORM parameterization  
                challenge.updated_at = datetime.utcnow()
                db.session.commit()
            else:
                return "Challenge not found", 404

        # Redirect to refresh the page after form submission
        return redirect(url_for('admin_screening.admin_page'))

    return render_template('admin_screening.html', challenges=challenges)
