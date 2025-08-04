from flask import Blueprint, render_template, redirect, url_for, flash, session
from db_handler import insert_challenge, check_and_update_rate_limit  # Import the rate limiting function
from file_upload import save_file  # Import file upload logic
from input_sanitizer import validate_challenge_input  # Protects against injection attacks
from auth_decorators import login_required  # Import centralized authentication decorator
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField
from flask_wtf.file import FileField, FileAllowed
from wtforms.validators import DataRequired, Length

# Create a Blueprint for the challenge form
challenge_bp = Blueprint('challenge', __name__, template_folder='templates')

# Authentication decorator is now imported from auth_decorators.py

# WTForm for Challenge - Protects against malformed input and enforces data validation
class ChallengeForm(FlaskForm):
    challenge_name = StringField('Challenge Name', validators=[DataRequired(), Length(max=100)])  # Protects against empty names and buffer overflow
    description = TextAreaField('Description', validators=[DataRequired(), Length(max=500)])  # Protects against empty descriptions and excessive length
    completion_criteria = TextAreaField('Completion Criteria', validators=[DataRequired(), Length(max=300)])  # Protects against undefined criteria and length attacks
    media = FileField('Media', validators=[FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'mp4', 'mov'], 'Images and videos only!')])  # Protects against dangerous file uploads

@challenge_bp.route('/', methods=['GET', 'POST'])
@login_required  # Protects against unauthorized challenge creation
def create_challenge():
    # Check if the user has exceeded the rate limit before proceeding - Protects against spam/DoS attacks
    user_id = session.get('user_id')  # Get the user_id from the session
    if user_id and not check_and_update_rate_limit(user_id):
        return "Too Many Requests", 429  # 429 Too Many Requests if rate limit is exceeded - Protects against abuse

    form = ChallengeForm()
    if form.validate_on_submit():
        # Sanitize form input - Protects against injection attacks
        form_data = {
            'challenge_name': form.challenge_name.data,
            'description': form.description.data,
            'completion_criteria': form.completion_criteria.data
        }
        sanitized_data = validate_challenge_input(form_data)
        
        challenge_name = sanitized_data.get('challenge_name', '')
        description = sanitized_data.get('description', '')
        completion_criteria = sanitized_data.get('completion_criteria', '')

        # Handle media file upload
        media_file = form.media.data
        media_filename = None

        if media_file:
            try:
                media_filename = save_file(media_file)
            except ValueError as e:
                flash(str(e), 'danger')
                return render_template('challenge.html', form=form)

        insert_challenge(challenge_name, description, completion_criteria, media_filename)
        return redirect(url_for('challenge.success'))

    elif form.is_submitted():
        flash('Please correct the errors in the form.', 'danger')

    return render_template('challenge.html', form=form)

@challenge_bp.route('/success')
def success():
    return "Challenge created successfully!"
