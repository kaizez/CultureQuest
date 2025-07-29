from flask import Blueprint, render_template
from init_db import fetch_challenges  # Fetch function from init_db.py to get challenges

# Create a Blueprint for the event page
event_bp = Blueprint('event', __name__, template_folder='templates')

@event_bp.route('/')
def event_page():
    # Fetch all approved challenges from the database
    challenges = fetch_challenges()

    # Filter out only the approved challenges
    challenges = fetch_challenges(status_filter='Approved')  # Only approved challenges

    # Get the latest approved challenge (the first one in the list)
    latest_challenge = challenges[0] if challenges else None

    # Get the rest of the approved challenges (excluding the latest one)
    other_challenges = challenges[1:5]  # Get up to 4 more

    return render_template('event.html', latest_challenge=latest_challenge, other_challenges=other_challenges)
