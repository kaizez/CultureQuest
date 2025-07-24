from flask import Blueprint, render_template
import shelve

# Create a Blueprint for the admin screening page
admin_screening_bp = Blueprint('admin_screening', __name__, template_folder='templates')

@admin_screening_bp.route('/')
def admin_page():
    # Access shelve database to fetch all challenges
    with shelve.open('challenges.db', 'r') as db:
        challenges = [challenge for challenge in db.values()]

    return render_template('admin_screening.html', challenges=challenges)
