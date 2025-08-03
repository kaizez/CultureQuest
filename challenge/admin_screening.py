from flask import Blueprint, render_template, request, redirect, url_for, session
from db_handler import fetch_challenges, update_challenge_status, check_and_update_rate_limit  # Import necessary functions
from functools import wraps
import sqlite3

# Create a Blueprint for the admin screening page
admin_screening_bp = Blueprint('admin_screening', __name__, template_folder='templates')

# Login required decorator (simplified to just check if user is logged in)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if 'username' not in session or 'email' not in session:
            return redirect('/login')
        # Allow access for any logged-in user
        return f(*args, **kwargs)
    return decorated_function

@admin_screening_bp.route('/', methods=['GET', 'POST'])
@login_required
def admin_page():
    # Check if the user has exceeded the rate limit before proceeding
    email = session.get('email')  # Get the user's email from the session
    if email and not check_and_update_rate_limit(email):
        return "Too Many Requests", 429  # 429 Too Many Requests if rate limit is exceeded

    # Fetch all unapproved challenges from the database
    challenges = fetch_challenges(status_filter='On Hold')  # Only unapproved challenges

    # Handle form submission for updating challenge status or comments
    if request.method == 'POST':
        challenge_id = request.form.get('challenge_id')
        status = request.form.get('status')
        comments = request.form.get('comments')
        points = request.form.get('points')

        # Validate and sanitize input
        try:
            challenge_id = int(challenge_id)
        except (TypeError, ValueError):
            return "Invalid challenge ID", 400

        try:
            points = int(points) if points is not None and points != '' else None
        except (TypeError, ValueError):
            return "Invalid points value", 400

        # If a status is provided (Approve, Reject, or On Hold), update status and comments
        if status:
            update_challenge_status(challenge_id, status, comments, points)
        else:
            # If only comments are provided, update comments without changing the status
            with sqlite3.connect('challenges.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''UPDATE challenges SET comments = ?, points = ? WHERE id = ?''',
                               (comments, points, challenge_id))  # Fixed: pass points and challenge_id as parameters
                conn.commit()

        # Redirect to refresh the page after form submission
        return redirect(url_for('admin_screening.admin_page'))

    return render_template('admin_screening.html', challenges=challenges)
