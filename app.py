from flask import Flask, render_template, request, redirect, url_for, flash, Response, session, jsonify
import os
import json
from forms import SubmissionForm, AcceptChallengeForm, CommentForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils import *
from db import db, init_db
from werkzeug.utils import secure_filename
import threading
from models import Challenge, ChallengeResponse, Comment
import tempfile
from sqlalchemy import or_

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
    'DATABASE_URL',
    'mysql+pymysql://flask_user:your_password@localhost/challenges_hub_db'
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['RECAPTCHA_SITE_KEY'] = '6LfyDo0rAAAAAC4VmJwx3fvFKhhfXYc3GVjqaO8q'
app.config['RECAPTCHA_SECRET_KEY'] = '6LfyDo0rAAAAAD9Mc3idU9TyOv4UcbDEicyVSe0a'

# --- Extensions Initialization ---
db.init_app(app) # Connect the db object to the app

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)

@app.errorhandler(429)
def ratelimit_handler(e):
    session['last_rate_limit'] = {
        'endpoint': request.endpoint,
        'timestamp': time.time()
    }
    flash("You have made too many requests recently. Please wait a moment and try again.", "warning")
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/challenges')
def challenges():
    all_challenges = Challenge.query.all()
    new_challenges = [c for c in all_challenges if c.status == 'NEW']
    current_challenges = [c for c in all_challenges if c.status in ['IN PROGRESS', 'NEEDS REVIEW']]
    done_challenges = [c for c in all_challenges if c.status == 'COMPLETED']

    return render_template('chall_hub.html',
                           new_challenges=new_challenges,
                           current_challenges=current_challenges,
                           done_challenges=done_challenges)

@app.route('/challenges/<string:challenge_id>')
def challenge_description(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    form = AcceptChallengeForm()
    more_challenges = Challenge.query.filter(Challenge.id != challenge_id, Challenge.status == 'NEW').limit(3).all()
    approved_comments = challenge.comments.filter_by(status='APPROVED').order_by(Comment.timestamp.desc()).all()

    return render_template('challenge_description.html',
                           challenge=challenge,
                           more_challenges=more_challenges,
                           form=form,
                           comments=approved_comments)

@app.route('/wip-challenges/<string:challenge_id>')
def wip_challenge_details(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    more_challenges = Challenge.query.filter(Challenge.id != challenge_id).limit(3).all()
    comment_form = CommentForm()
    rate_limit_info = session.pop('last_rate_limit', None)

    if rate_limit_info and rate_limit_info.get('endpoint') != 'add_comment_to_wip_challenge':
        rate_limit_info = None

    return render_template('challenge_wip.html',
                           challenge=challenge,
                           more_challenges=more_challenges,
                           comment_form=comment_form,
                           rate_limit_info=rate_limit_info)

@app.route('/wip-challenges/<string:challenge_id>/add-comment', methods=['POST'])
@limiter.limit("5 per minute") # Adjusted rate limit
def add_comment_to_wip_challenge(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    form = CommentForm()

    # We still validate the form, which also checks the CSRF token
    if form.validate_on_submit():
        recaptcha_token = request.form.get('g_recaptcha_response')
        if not recaptcha_token:
            return jsonify({'success': False, 'message': 'reCAPTCHA token is missing.'}), 400

        is_human, score = verify_recaptcha(app, recaptcha_token, action='comment')
        if not is_human:
            return jsonify({'success': False, 'message': 'reCAPTCHA verification failed. Please try again.'}), 400

        # If validation and reCAPTCHA pass, add the comment
        new_comment_text = form.comment.data
        new_comment = Comment(
            text=new_comment_text,
            challenge_id=challenge.id,
            user_id='user' # Replace with actual user ID when auth is implemented
        )
        db.session.add(new_comment)
        try:
            db.session.commit()
            flash('Your comment has been submitted for review.', 'info')
            session.pop('last_rate_limit', None)
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            print(f"Error adding comment: {e}")
            return jsonify({'success': False, 'message': 'A server error occurred while adding the comment.'}), 500
    else:
        # If form validation fails, return the errors as JSON
        errors = [error for field in form.errors.values() for error in field]
        return jsonify({'success': False, 'message': errors[0] if errors else 'Invalid data submitted.'}), 422

@app.route('/submit-challenge/<string:challenge_id>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def challenge_submission(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    form = SubmissionForm(request.form)

    if request.method == 'POST':
        if 'uploaded_file' in request.files:
            form.uploaded_file.data = request.files['uploaded_file']
        
        reflection_text = form.reflection_story.data

        if form.validate_on_submit():
            recaptcha_token = request.form.get('g_recaptcha_response')
            if not recaptcha_token:
                flash('reCAPTCHA token is missing.', 'danger')

            is_human, score = verify_recaptcha(app, recaptcha_token, action='submit_challenge')
            if not is_human:
                flash('reCAPTCHA verification failed. Please try again.', 'danger')
            error_message = None
            uploaded_file = form.uploaded_file.data
            if uploaded_file:
                detected_file_type = check_file_signature(uploaded_file.stream)
                allowed_signature_types = ['jpeg', 'png', 'mp4', 'pdf', 'docx', 'xlsx', 'pptx', 'zip']
                allowed_signatures = ['jpeg', 'png', 'mp4', 'pdf', 'docx', 'xlsx', 'pptx']
                
                # Check if the detected signature type is among the allowed types
                if detected_file_type == 'error_reading_file':
                    error_message = "Error reading uploaded file for signature verification."
                    flash(error_message, 'danger')
                elif detected_file_type == 'unknown' or detected_file_type not in allowed_signature_types or not allowed_file(uploaded_file.filename):
                    error_message = f"File signature mismatch. Detected: {detected_file_type}. Allowed types for submission: {', '.join(allowed_signatures)}."
                    flash(error_message, 'danger')
                else:
                    try:
                        file_content = uploaded_file.read()
                        filename = secure_filename(uploaded_file.filename)

                        new_response = ChallengeResponse(
                            challenge_id=challenge.id,
                            filename=filename,
                            file_content=file_content,
                            reflection=reflection_text
                        )
                        db.session.add(new_response)

                        db.session.flush()

                        # Start the scan in a background thread
                        scan_thread = threading.Thread(target=scan_file_in_background, args=(app, new_response.id, db))
                        scan_thread.start()

                        # Update challenge status
                        challenge.status = 'COMPLETED'
                        challenge.progress_percent = 100
                        db.session.commit()
                        
                        flash(f'Challenge "{challenge.title}" submitted successfully!', 'success')
                        return redirect(url_for('challenges'))

                    except Exception as e:
                        print(e)
                        db.session.rollback()
                        flash(f"An unexpected error occurred during file processing: {e}", 'danger')
                        
            # Update challenge status only if no critical errors occurred during scanning
            if not error_message: 
                challenge.status = 'DONE'
                challenge.progress_percent = 100
                try:
                    db.session.commit()
                    flash(f'Your challenge "{challenge.title}" has been successfully completed and submitted!', 'success')
                    return redirect(url_for('index'))
                except Exception as e:
                    print(e)
                    db.session.rollback()
                    flash(f'Error updating challenge status: {e}', 'danger')
                    print(f"Error updating challenge status: {e}")
            else:
                pass
        else:
            print("Form validation failed.")
            print(form.errors)
            flash('Please correct the errors below.', 'danger')

    return render_template('challenge_submission.html', challenge=challenge, form=form)

@app.route('/challenges/accept/<string:challenge_id>', methods=['POST'])
def accept_challenge(challenge_id):
    form = AcceptChallengeForm()
    if form.validate_on_submit():
        challenge = Challenge.query.get_or_404(challenge_id)
        
        challenge.status = 'IN PROGRESS'
        challenge.progress_percent = 5
        challenge.duration_left = challenge.duration
        challenge.xp = challenge.xp or 0
        
        if not challenge.your_progress_next_steps:
            challenge.your_progress_next_steps = json.dumps([
                {"text": "Review challenge requirements.", "completed": False},
                {"text": f"Start working on '{challenge.title}'!", "completed": False}
            ])
        
        if not challenge.resources_for_you:
            challenge.resources_for_ou = json.dumps([
                {"text": "Challenge Starter Guide", "link": "#"},
                {"text": "Community Support Forum", "link": "#"}
            ])

        try:
            db.session.commit()
            flash(f'You have successfully accepted the "{challenge.title}" challenge! Head to My Challenges to see your progress.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error accepting challenge: {e}', 'danger')
            print(f"Error accepting challenge: {e}")
    else:
        flash('Invalid request. Please try again.', 'danger')

    return redirect(url_for('wip_challenge_details', challenge_id=challenge.id))

@app.route('/report-comment/<string:comment_id>', methods=['POST'])
@limiter.limit("15 per minute")
def report_comment(comment_id):
    comment = db.session.get(Comment, comment_id)
    if comment:
        comment.status = 'REPORTED'
        db.session.commit()
        flash('Comment has been reported for review.', 'info')
    else:
        flash('Comment not found.', 'danger')
    return redirect(url_for('challenges'))




@app.route('/admin/download-file/<string:response_id>')
def download_file(response_id):
    response_record = db.session.get(ChallengeResponse, response_id)
    if not response_record or not response_record.file_content:
        flash("File not found.", "danger")
        return redirect(url_for('admin_uploaded_content_list'))
    
    return Response(
        response_record.file_content,
        mimetype='application/octet-stream',
        headers={"Content-Disposition": f"attachment;filename={response_record.filename}"}
    )

@app.route('/admin/rescan-file/<string:response_id>', methods=['POST'])
@limiter.limit("5 per minute")
def admin_rescan_file(response_id):
    response = db.session.get(ChallengeResponse, response_id)
    if not response:
        flash("Response not found.", "danger")
        return redirect(url_for('admin_uploaded_content_list'))

    if not response.file_content:
        flash("Cannot re-scan. File content is missing from the database.", "danger")
        return redirect(url_for('admin_uploaded_content_detail', response_id=response.id))

    try:
        # Start the scan in a background thread
        scan_thread = threading.Thread(target=scan_file_in_background, args=(app, response.id, db))
        scan_thread.start()
        flash(f"Re-scan initiated for response ID: {response.id}. Results will update shortly.", 'info')
    except Exception as e:
        flash(f"Failed to start re-scan: {e}", 'danger')

    return redirect(url_for('admin_uploaded_content_detail', response_id=response.id))

@app.route('/admin/uploaded-content')
def admin_uploaded_content_list():
    responses = ChallengeResponse.query.order_by(ChallengeResponse.submission_date.desc()).all()
    return render_template('admin_chall.html', responses=responses)

@app.route('/admin/uploaded-content/<string:response_id>')
def admin_uploaded_content_detail(response_id):
    response = db.session.get(ChallengeResponse, response_id)
    if not response:
        flash(f"Response with ID {response_id} not found.", "danger")
        return redirect(url_for('admin_uploaded_content_list'))

    scan_results = None
    scan_summary = None 
    if response.virustotal_scan_results:
        scan_results = json.loads(response.virustotal_scan_results)
        if scan_results and 'data' in scan_results and 'attributes' in scan_results['data']:
             scan_summary = scan_results['data']['attributes'].get('stats', {})

    return render_template('admin_chall_details.html', 
                           response=response, 
                           challenge=response.challenge,
                           scan_results=scan_results, 
                           scan_summary=scan_summary)

@app.route('/admin/moderate-comments')
def admin_moderate_comments():
    pending_comments = Comment.query.filter(or_(Comment.status == 'PENDING', Comment.status == 'REPORTED')
    ).order_by(Comment.timestamp.desc()).all()
    return render_template('admin_moderate.html', comments=pending_comments)

@app.route('/admin/update-comment-status/<string:comment_id>/<string:action>', methods=['POST'])
def admin_update_comment_status(comment_id, action):
    comment = db.session.get(Comment, comment_id)
    if not comment:
        flash("Comment not found.", "danger")
        return redirect(url_for('admin_moderate_comments'))

    if action == 'approve':
        comment.status = 'APPROVED'
        flash(f"Comment approved.", 'success')
    elif action == 'reject':
        comment.status = 'REJECTED'
        flash(f"Comment rejected.", 'warning')
    else:
        flash("Invalid action.", "danger")
    
    db.session.commit()
    return redirect(url_for('admin_moderate_comments'))

    
if __name__ == '__main__':
    init_db(app)
    app.run(debug=True)