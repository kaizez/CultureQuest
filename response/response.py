from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from datetime import datetime, timedelta
from .forms import SubmissionForm, AcceptChallengeForm, CommentForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .utils import *
from .db import db_session
from werkzeug.utils import secure_filename
import threading
from .models import ChallengeResponse, Comment
from sqlalchemy import select, desc, create_engine, text, inspect
from auth_utils import require_login, get_user_id

response_bp = Blueprint('response', __name__, static_url_path='/response/static', static_folder='static')

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
@require_login
def challenges():
    query = text(f"SELECT * FROM challenge_submissions")
    result = db_session.execute(query)
    rows = result.fetchall()
    # user_id = session.get('user_id') # need to test whether return in '' or js str
    user_id = r'"a56b84f3-2b4c-4670-b3b6-6894af8f78dc"'
    query = text(f"SELECT points from user_points where user_id={user_id}")
    points = db_session.execute(query).fetchone()
    # new_challenges = [c for c in all_challenges if c.status == 'NEW']
    # current_challenges = [c for c in all_challenges if c.status in ['IN PROGRESS', 'NEEDS REVIEW']]
    # done_challenges = [c for c in all_challenges if c.status == 'COMPLETED']
    # user_points = db.session.execute(select('user_points').filter(user_id = user_id)).scalars.first()
    new_challenges = [c for c in rows]
    current_challenges = [c for c in rows]
    done_challenges = [c for c in rows]

    return render_template('chall_hub.html',
                           new_challenges=new_challenges,
                           current_challenges=current_challenges,
                           done_challenges=done_challenges,
                           points=points)

@response_bp.route('/challenges/<string:challenge_id>')
@require_login
def challenge_description(challenge_id):
    query = text(f"SELECT * FROM challenge_submissions where id = '{challenge_id}'")
    result = db_session.execute(query)
    challenge = result.fetchone()
    # all_challenges_stmt = select(Challenge)
    # all_challenges = db_session.execute(all_challenges_stmt).scalars().all()
    # new_challenges = [c for c in all_challenges if c.status == 'NEW']
    # current_challenges = [c for c in all_challenges if c.status in ['IN PROGRESS', 'NEEDS REVIEW']]
    # done_challenges = [c for c in all_challenges if c.status == 'COMPLETED']
    if not challenge:
        return "Challenge not found", 404
    form = AcceptChallengeForm()
    # approved_comments = challenge.comments.filter(status='APPROVED').order_by(Comment.timestamp.desc()).all()

    return render_template('challenge_description.html',
                           challenge=challenge,
                           form=form,
                           comments=None)

@response_bp.route('/wip-challenges/<string:challenge_id>')
@require_login
def wip_challenge_details(challenge_id):
    query = text(f"SELECT * FROM challenge_submissions where id = '{challenge_id}'")
    result = db_session.execute(query)
    challenge = result.fetchone()
    comment_form = CommentForm()
    rate_limit_info = session.pop('last_rate_limit', None)

    if rate_limit_info and rate_limit_info.get('endpoint') != 'add_comment_to_wip_challenge':
        rate_limit_info = None

    return render_template('challenge_wip.html',
                           challenge=challenge,
                           comment_form=comment_form,
                           rate_limit_info=rate_limit_info,
                           config=current_app.config)

@response_bp.route('/wip-challenges/<string:challenge_id>/add-comment', methods=['POST'])
@require_login
@limiter.limit("5 per minute") 
def add_comment_to_wip_challenge(challenge_id):
    query = text(f"SELECT * FROM challenge_submissions where id = '{challenge_id}'")
    result = db_session.execute(query)
    challenge = result.fetchone()
    form = CommentForm()
    
    if form.validate_on_submit():
        recaptcha_token = request.form.get('g_recaptcha_response')
        if not recaptcha_token:
            return jsonify({'success': False, 'message': 'reCAPTCHA token is missing.'}), 400

        is_human, score = verify_recaptcha(recaptcha_token, action='comment')
        if not is_human:
            return jsonify({'success': False, 'message': 'reCAPTCHA verification failed. Please try again.'}), 400

        
        new_comment_text = form.comment.data
        new_comment = Comment(
            text=new_comment_text,
            challenge_id=challenge.id,
            user_id='user' 
        )
        db_session.add(new_comment)
        try:
            db_session.commit()
            flash('Your comment has been submitted for review.', 'info')
            session.pop('last_rate_limit', None)
            return jsonify({'success': True})
        except Exception as e:
            db_session.rollback()
            print(f"Error adding comment: {e}")
            return jsonify({'success': False, 'message': 'A server error occurred while adding the comment.'}), 500
    else:
        
        errors = [error for field in form.errors.values() for error in field]
        return jsonify({'success': False, 'message': errors[0] if errors else 'Invalid data submitted.'}), 422

@response_bp.route('/submit-challenge/<string:challenge_id>', methods=['GET', 'POST'])
@require_login
@limiter.limit("5 per minute")
def challenge_submission(challenge_id):
    query = text(f"SELECT * FROM challenge_submissions where id = '{challenge_id}'")
    result = db_session.execute(query)
    challenge = result.fetchone()

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
                        db_session.add(new_response)
                        
                        # challenge.status = 'COMPLETED'
                        # challenge.progress_percent = 100
                        db_session.commit()
                
                        if new_response.file_content:
                            app_instance = current_app._get_current_object()
                            scan_thread = threading.Thread(target=scan_file_in_background, args=(app_instance, new_response.id))
                            scan_thread.start()
                        
                        flash(f'Challenge "{challenge.challenge_name}" submitted successfully!', 'success')
                        return redirect(url_for('response.challenges'))

                    except Exception as e:
                        print(e)
                        db_session.rollback()
                        flash(f"An unexpected error occurred during file processing: {e}", 'danger')
                        
            
            if not error_message: 
                # challenge.status = 'DONE'
                # challenge.progress_percent = 100
                try:
                    # db_session.commit()
                    flash(f'Your challenge "{challenge.challenge_name}" has been successfully completed and submitted!', 'success')
                    return redirect(url_for('response.challenges'))
                except Exception as e:
                    print(e)
                    db_session.rollback()
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
@require_login
def accept_challenge(challenge_id):
    form = AcceptChallengeForm()
    if form.validate_on_submit():
        query = text(f"SELECT * FROM challenge_submissions where id = '{challenge_id}'")
        result = db_session.execute(query)
        challenge = result.fetchone()
        
        # challenge.status = 'IN PROGRESS'
        # challenge.progress_percent = 5
        # challenge.xp = challenge.xp or 0
        
        
        try:
            db_session.commit()
            flash(f'You have successfully accepted the "{challenge.challenge_name}" challenge! Head to My Challenges to see your progress.', 'success')
        except Exception as e:
            db_session.rollback()
            flash(f'Error accepting challenge: {e}', 'danger')
            print(f"Error accepting challenge: {e}")
    else:
        flash('Invalid request. Please try again.', 'danger')

    return redirect(url_for('response.wip_challenge_details', challenge_id=challenge.id))

@response_bp.route('/report-comment/<string:comment_id>', methods=['POST'])
@require_login
@limiter.limit("15 per minute")
def report_comment(comment_id):
    query = text(f"SELECT * FROM comment where id = '{comment_id}'")
    result = db_session.execute(query)
    comment = result.fetchone()
    if comment:
        comment.status = 'REPORTED'
        db_session.commit()
        flash('Comment has been reported for review.', 'info')
    else:
        flash('Comment not found.', 'danger')
    return redirect(url_for('response.challenges'))

