from flask import Blueprint, render_template, request, redirect, url_for
import shelve
from file_upload import save_file  # Import file upload logic

# Create a Blueprint for the challenge form
challenge_bp = Blueprint('challenge', __name__, template_folder='templates')

# Upload folder for storing uploaded files
UPLOAD_FOLDER = 'static/uploads/'

@challenge_bp.route('/', methods=['GET', 'POST'])
def create_challenge():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        description = request.form['description']

        # Handle media file upload
        media_file = request.files['media']
        media_filename = None

        if media_file:
            try:
                # Save the file and get its filename
                media_filename = save_file(media_file)
            except ValueError as e:
                return str(e)

        # Store the challenge data in a shelve database (or other storage)
        with shelve.open('challenges.db', writeback=True) as db:
            challenge_id = len(db) + 1  # Simple auto-increment ID
            db[str(challenge_id)] = {
                'name': name,
                'email': email,
                'phone': phone,
                'media': media_filename,
                'description': description
            }

        return redirect(url_for('challenge.success'))

    return render_template('challenge.html')

@challenge_bp.route('/success')
def success():
    return "Challenge created successfully!"
