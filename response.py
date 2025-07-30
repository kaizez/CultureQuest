from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from datetime import datetime, timedelta
from forms import SubmissionForm, AcceptChallengeForm, CommentForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils import *
from db import db
from werkzeug.utils import secure_filename
import threading
from models import Challenge, ChallengeResponse, Comment

response_bp = Blueprint('challenge', __name__, template_folder='templates')

limiter = Limiter(
    app=current_app,
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)

@response_bp.errorhandler(429)
def ratelimit_handler(e):
    session['last_rate_limit'] = {
        'endpoint': request.endpoint,
        'timestamp': time.time()
    }
    flash("You have made too many requests recently. Please wait a moment and try again.", "warning")
    return redirect(url_for('landing_page'))

@response_bp.route('/challenges')
def challenges():
    all_challenges = Challenge.query.all()
    new_challenges = [c for c in all_challenges if c.status == 'NEW']
    current_challenges = [c for c in all_challenges if c.status in ['IN PROGRESS', 'NEEDS REVIEW']]
    done_challenges = [c for c in all_challenges if c.status == 'COMPLETED']

    return render_template('chall_hub.html',
                           new_challenges=new_challenges,
                           current_challenges=current_challenges,
                           done_challenges=done_challenges)

@response_bp.route('/challenges/<string:challenge_id>')
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

@response_bp.route('/wip-challenges/<string:challenge_id>')
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

@response_bp.route('/wip-challenges/<string:challenge_id>/add-comment', methods=['POST'])
@limiter.limit("5 per minute") # Adjusted rate limit
def add_comment_to_wip_challenge(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    form = CommentForm()

    # We still validate the form, which also checks the CSRF token
    if form.validate_on_submit():
        recaptcha_token = request.form.get('g_recaptcha_response')
        if not recaptcha_token:
            return jsonify({'success': False, 'message': 'reCAPTCHA token is missing.'}), 400

        is_human, score = verify_recaptcha(recaptcha_token, action='comment')
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

@response_bp.route('/submit-challenge/<string:challenge_id>', methods=['GET', 'POST'])
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

            is_human, score = verify_recaptcha(recaptcha_token, action='submit_challenge')
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

                        # Update challenge status
                        challenge.status = 'COMPLETED'
                        challenge.progress_percent = 100
                        db.session.commit()
                
                        if new_response.file_content:
                            app_instance = current_app._get_current_object()
                            scan_thread = threading.Thread(target=scan_file_in_background, args=(app_instance, new_response.id))
                            scan_thread.start()
                        
                        flash(f'Challenge "{challenge.title}" submitted successfully!', 'success')
                        return redirect(url_for('challenge.challenges'))

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
                    return redirect(url_for('challenge.challenges'))
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

@response_bp.route('/challenges/accept/<string:challenge_id>', methods=['POST'])
def accept_challenge(challenge_id):
    form = AcceptChallengeForm()
    if form.validate_on_submit():
        challenge = Challenge.query.get_or_404(challenge_id)
        
        challenge.status = 'IN PROGRESS'
        challenge.progress_percent = 5
        challenge.xp = challenge.xp or 0
        
        duration_parts = challenge.duration.split()
        if len(duration_parts) == 2 and duration_parts[1] in ['days', 'weeks']:
            value = int(duration_parts[0])
            if duration_parts[1] == 'days':
                end_date = datetime.utcnow() + timedelta(days=value)
            else:
                end_date = datetime.utcnow() + timedelta(weeks=value)
            
            challenge.duration_left = f"{(end_date - datetime.utcnow()).days} days left"
        else:
            challenge.duration_left = challenge.duration

        try:
            db.session.commit()
            flash(f'You have successfully accepted the "{challenge.title}" challenge! Head to My Challenges to see your progress.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error accepting challenge: {e}', 'danger')
            print(f"Error accepting challenge: {e}")
    else:
        flash('Invalid request. Please try again.', 'danger')

    return redirect(url_for('challenge.wip_challenge_details', challenge_id=challenge.id))

@response_bp.route('/report-comment/<string:comment_id>', methods=['POST'])
@limiter.limit("15 per minute")
def report_comment(comment_id):
    comment = db.session.get(Comment, comment_id)
    if comment:
        comment.status = 'REPORTED'
        db.session.commit()
        flash('Comment has been reported for review.', 'info')
    else:
        flash('Comment not found.', 'danger')
    return redirect(url_for('challenge.challenges'))

