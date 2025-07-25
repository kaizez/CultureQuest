from flask import Blueprint, render_template
from init_db import fetch_challenges  # Use the fetch function from init_db.py

# Create a Blueprint for the admin screening page
admin_screening_bp = Blueprint('admin_screening', __name__, template_folder='templates')

@admin_screening_bp.route('/')
def admin_page():
    # Fetch all challenges from SQLite database using fetch_challenges
    challenges = fetch_challenges()

    return render_template('admin_screening.html', challenges=challenges)
