from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, current_app
from .forms import SubmissionForm, AcceptChallengeForm, CommentForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .utils import *
from .db import db_session
from werkzeug.utils import secure_filename
import threading
from .models import ChallengeResponse, Comment, ChallegeStatus
from auth_utils import require_login, get_user_id, get_username
from sqlalchemy import text
import base64
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
    return redirect(url_for('response.challenges'))

@response_bp.route('/challenges')
@require_login
def challenges():
        
    user_id = get_user_id() if get_user_id() else r"a56b84f3-2b4c-4670-b3b6-6894af8f78dc"
    print(user_id)
    query_user_statuses = text("SELECT challenge_id, status FROM challenge_status WHERE user_id = :user_id")
    status_results = db_session.execute(query_user_statuses, {"user_id": user_id}).fetchall()
    challenge_statuses = {str(row.challenge_id): row.status for row in status_results}

    query_all_challenges = text("SELECT * FROM challenge_submissions")
    all_challenges_results = db_session.execute(query_all_challenges).fetchall()

    new_challenges = []
    current_challenges = []
    done_challenges = []

    for challenge_row in all_challenges_results:
        challenge_dict = dict(challenge_row._mapping)

        if challenge_dict.get('media_data'):
            encoded_image = base64.b64encode(challenge_dict['media_data']).decode('utf-8')
            challenge_dict['encoded_image'] = encoded_image
        else:
            challenge_dict['encoded_image'] = None

        status = challenge_statuses.get(str(challenge_dict['id']))

        if status is None:
            new_challenges.append(challenge_dict)
        elif status == 'ACCEPTED':
            current_challenges.append(challenge_dict)
        elif status == 'COMPLETED' or status == 'APPROVED' or status == 'REJECTED':
            done_challenges.append(challenge_dict)

    query_points = text("SELECT points from user_points where user_id=:user_id")
    points_result = db_session.execute(query_points, {"user_id": user_id}).fetchone()
    points = points_result if points_result else {'points': 0}

    return render_template(
        'chall_hub.html',
        new_challenges=new_challenges,
        current_challenges=current_challenges,
        done_challenges=done_challenges,
        points=points
    )

@response_bp.route('/challenges/<string:challenge_id>')
@require_login
def challenge_description(challenge_id):
    query = text(f"SELECT * FROM challenge_submissions where id = :challenge_id")
    result = db_session.execute(query, {"challenge_id": challenge_id})
    challenge = result.fetchone()
    if not challenge:
        return "Challenge not found", 404
    form = AcceptChallengeForm()

    query = text(f"SELECT media_data FROM challenge_submissions where id = :challenge_id")
    image_data = db_session.execute(query, {"challenge_id": challenge_id}).fetchone()
    if image_data[0]:
        encoded_image = base64.b64encode(image_data[0]).decode('utf-8')
    else:
        encoded_image = None


    return render_template('challenge_description.html',
                            challenge=challenge,
                            form=form,
                            comments=None,
                            encoded_image=encoded_image)

@response_bp.route('/wip-challenges/<string:challenge_id>')
@require_login
def wip_challenge_details(challenge_id):
    query = text("SELECT * FROM challenge_submissions where id = :challenge_id")
    result = db_session.execute(query, {"challenge_id": challenge_id})
    challenge = result.fetchone()

    query = text("SELECT * from comment where challenge_id = :challenge_id and status='APPROVED'")
    comments = db_session.execute(query, {"challenge_id": challenge_id}).fetchall()

    comment_form = CommentForm()
    rate_limit_info = session.pop('last_rate_limit', None)

    if rate_limit_info and rate_limit_info.get('endpoint') != 'add_comment_to_wip_challenge':
        rate_limit_info = None

    query = text(f"SELECT media_data FROM challenge_submissions where id = :challenge_id")
    image_data = db_session.execute(query, {"challenge_id": challenge_id}).fetchone()
    encoded_image = base64.b64encode(image_data[0]).decode('utf-8')
    
    return render_template('challenge_wip.html',
                           challenge=challenge,
                           comment_form=comment_form,
                           rate_limit_info=rate_limit_info,
                           config=current_app.config,
                           approved_comments=comments,
                           encoded_image=encoded_image)

@response_bp.route('/wip-challenges/<string:challenge_id>/add-comment', methods=['POST'])
@require_login
@limiter.limit("5 per minute") 
def add_comment_to_wip_challenge(challenge_id):
    user_id = get_user_id() if get_user_id() else r"a56b84f3-2b4c-4670-b3b6-6894af8f78dc"
    query = text(f"SELECT * FROM challenge_submissions where id = :challenge_id")
    result = db_session.execute(query, {"challenge_id": challenge_id})
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
            challenge_id=challenge_id,
            challenge_name=challenge.challenge_name,
            username=get_username(),
            user_id=user_id 
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
    query = text(f"SELECT * FROM challenge_submissions where id = :challenge_id")
    result = db_session.execute(query, {"challenge_id": challenge_id})
    challenge = result.fetchone()
    user_id = get_user_id() if get_user_id() else r"a56b84f3-2b4c-4670-b3b6-6894af8f78dc"

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
                            user_id = user_id,
                            filename=filename,
                            file_content=file_content,
                            reflection=reflection_text
                        )
                        db_session.add(new_response)
                        
                        db_session.commit()
                        query = text("UPDATE challenge_status SET status = 'COMPLETED' WHERE user_id = :user_id and challenge_id = :challenge_id")
                        db_session.execute(query, {"user_id": user_id, "challenge_id": challenge_id})
                        
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
                try:
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
        query = text(f"SELECT * FROM challenge_submissions where id = :challenge_id")
        result = db_session.execute(query, {"challenge_id": challenge_id})
        challenge = result.fetchone()        
        
        user_id = get_user_id() if get_user_id() else r"a56b84f3-2b4c-4670-b3b6-6894af8f78dc"
        try:
            update_status = ChallegeStatus(
                challenge_id=challenge_id,
                user_id = user_id,
                status = "ACCEPTED"
            )
            db_session.add(update_status)
            
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
    comment = db_session.get(Comment, comment_id)
    if comment:
        comment.status = 'REPORTED'
        db_session.commit()
        flash('Comment has been reported for review.', 'info')
    else:
        flash('Comment not found.', 'danger')
    return redirect(url_for('response.challenges'))

@response_bp.route('/track_points')
@require_login
def track_points():
    user_id = get_user_id() if get_user_id() else r"a56b84f3-2b4c-4670-b3b6-6894af8f78dc"
    username = get_username() if get_username() else "Iamwk"

    query = text("select points from user_points WHERE user_id = :user_id")
    user_points = db_session.execute(query, {"user_id": user_id}).scalar()

    query = text("SELECT * FROM challenge_status WHERE user_id = :user_id ")
    status_records = db_session.execute(query, {"user_id": user_id}).fetchall()
    query = text("SELECT points FROM challenge_submissions WHERE id = :challenge_id")

    challenge_points = {}
    total_points = 0

    if status_records:
        challenge_ids = [str(record.challenge_id) for record in status_records]
        ids_list = ", ".join(challenge_ids)
        points_query = text(f"SELECT id, challenge_name, points FROM challenge_submissions WHERE id IN ({ids_list})")
        points_results = db_session.execute(points_query).fetchall()
        
        challenge_points = {
            row.id: {
                'name': row.challenge_name, 
                'points': row.points
            } 
            for row in points_results
        }
        
        total_points = sum(
            challenge_points.get(record.challenge_id, {}).get('points', 0) 
            for record in status_records 
            if record.status == 'COMPLETED'
        )

    return render_template('track_points.html', 
                           username = username,
                           user_points = user_points,
                         status_records=status_records,
                         challenge_points=challenge_points,
                         total_points=total_points)