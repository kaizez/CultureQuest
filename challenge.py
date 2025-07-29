from flask import Blueprint, render_template, request, redirect, url_for
from init_db import insert_challenge  # Use the insert function from init_db.py
from validation import validate_name, validate_phone  # Import validation functions
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

        # Validate name and phone fields
        if not validate_name(name):
            return "Invalid name. Only letters and spaces are allowed.", 400

        if not validate_phone(phone):
            return "Invalid phone number. Only digits are allowed.", 400

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
        insert_challenge(name, email, phone, description, media_filename)

        return redirect(url_for('challenge.success'))

    return render_template('challenge.html')

@challenge_bp.route('/success')
def success():
    return "Challenge created successfully!"
