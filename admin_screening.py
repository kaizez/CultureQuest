from flask import Blueprint, render_template, request, redirect, url_for
from db_handler import fetch_challenges, update_challenge_status  # Import necessary functions

# Create a Blueprint for the admin screening page
admin_screening_bp = Blueprint('admin_screening', __name__, template_folder='templates')

@admin_screening_bp.route('/', methods=['GET', 'POST'])
def admin_page():
    # Fetch all unapproved challenges from the database
    challenges = fetch_challenges(status_filter='On Hold')  # Only unapproved challenges

    # Handle form submission for updating challenge status or comments
    if request.method == 'POST':
        challenge_id = request.form.get('challenge_id')
        status = request.form.get('status')  # This will be None if no button was pressed
        comments = request.form.get('comments')

        # If a status is provided (Approve, Reject, or On Hold), update status and comments
        if status:
            update_challenge_status(challenge_id, status, comments)
        else:
            # If only comments are provided, update comments without changing the status
            with sqlite3.connect('challenges.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE challenges
                    SET comments = ?
                    WHERE id = ?
                ''', (comments, challenge_id))
                conn.commit()

        # Redirect to refresh the page after form submission
        return redirect(url_for('admin_screening.admin_page'))

    return render_template('admin_screening.html', challenges=challenges)
