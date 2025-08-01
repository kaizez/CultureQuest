from flask import Blueprint, render_template, request, redirect, url_for
from db_handler import insert_challenge  # Use the insert function from db_handler.py
from file_upload import save_file  # Import file upload logic

# Create a Blueprint for the challenge form
challenge_bp = Blueprint('challenge', __name__, template_folder='templates')

# Upload folder for storing uploaded files
UPLOAD_FOLDER = 'static/uploads/'

@challenge_bp.route('/', methods=['GET', 'POST'])
def create_challenge():
    if request.method == 'POST':
        challenge_name = request.form['challenge_name']
        description = request.form['description']
        completion_criteria = request.form['completion_criteria']

        # Handle media file upload
        media_file = request.files.get('media')
        media_filename = None

        if media_file and media_file.filename:
            try:
                # Save the file and get its filename
                media_filename = save_file(media_file)
            except ValueError as e:
                return str(e)

        # Insert challenge data into SQLite database using insert_challenge
        # We'll need to modify this to match the new fields
        insert_challenge(challenge_name, description, completion_criteria, media_filename)

        return redirect(url_for('challenge.success'))

    return render_template('challenge.html')

@challenge_bp.route('/success')
def success():
    return "Challenge created successfully!"
