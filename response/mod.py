from flask import Blueprint, render_template, redirect, url_for, flash, Response, current_app
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from .utils import *
from .db import db_session
import threading
from .models import Comment
from sqlalchemy import select, or_, desc
from auth_utils import require_admin
moderate_bp = Blueprint('moderate', __name__, template_folder='templates')

limiter = Limiter(
    app=current_app,
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)

@moderate_bp.route('/download-file/<string:response_id>')
@require_admin
def download_file(response_id):
    query = text("SELECT * FROM challenge_response WHERE id = :response_id")
    result = db_session.execute(query, {"response_id": response_id})
    response_record = result.fetchone()
    if not response_record or not response_record.file_content:
        flash("File not found.", "danger")
        return redirect(url_for('moderate.admin_uploaded_content_list'))
    
    return Response(
        response_record.file_content,
        mimetype='application/octet-stream',
        headers={"Content-Disposition": f"attachment;filename={response_record.filename}"}
    )

@moderate_bp.route('/rescan-file/<string:response_id>', methods=['POST'])
@require_admin
@limiter.limit("5 per minute")
def admin_rescan_file(response_id):
    query = text("SELECT * FROM challenge_response WHERE id = :response_id")
    result = db_session.execute(query, {"response_id": response_id})
    response = result.fetchone()
    if not response:
        flash("Response not found.", "danger")
        return redirect(url_for('moderate.admin_uploaded_content_list'))

    if not response.file_content:
        flash("Cannot re-scan. File content is missing from the database.", "danger")
        return redirect(url_for('moderate.admin_uploaded_content_detail', response_id=response.id))

    try:        
        app_instance = current_app._get_current_object()
        scan_thread = threading.Thread(target=scan_file_in_background, args=(app_instance, response.id))
        scan_thread.start()
        flash(f"Re-scan initiated for response ID: {response.id}. Results will update shortly.", 'info')
    except Exception as e:
        flash(f"Failed to start re-scan: {e}", 'danger')

    return redirect(url_for('moderate.admin_uploaded_content_detail', response_id=response.id))

@moderate_bp.route('/uploaded-content')
@require_admin
def admin_uploaded_content_list():        
    responses_stmt = select(ChallengeResponse).order_by(desc(ChallengeResponse.submission_date))
    responses = db_session.execute(responses_stmt).scalars().all()

    challenge_ids = {res.challenge_id for res in responses}
    challenge_titles = {}
    if challenge_ids:
        ids_list = ", ".join(map(str, challenge_ids))
        query = text(f"SELECT id, challenge_name FROM challenge_submissions WHERE id IN ({ids_list})")
        title_results = db_session.execute(query).fetchall()
        challenge_titles = {row[0]: row[1] for row in title_results}

    challenge_statuses = {}
    if responses:
        challenge_user_pairs = [(res.challenge_id, res.user_id) for res in responses]
        
        for challenge_id, user_id in challenge_user_pairs:
            query = text("SELECT status FROM challenge_status WHERE challenge_id = :challenge_id AND user_id = :user_id")
            result = db_session.execute(query, {"challenge_id": challenge_id, "user_id": user_id}).fetchone()
            
            status_key = f"{challenge_id}_{user_id}"
            challenge_statuses[status_key] = result.status if result else 'PENDING'

    for response in responses:
        query = text(f"SELECT challenge_name FROM challenge_submissions where id = :response_id")
        challenge = db_session.execute(query, {"response_id": response.challenge_id}).fetchone()
        response.challenge_title = challenge[0]

    return render_template('admin_chall.html', responses=responses, challenge_statuses=challenge_statuses)

@moderate_bp.route('/uploaded-content/<string:response_id>')
@require_admin
def admin_uploaded_content_detail(response_id):
    query = text("SELECT * FROM challenge_response WHERE id = :response_id")
    result = db_session.execute(query, {"response_id": response_id})
    response = result.fetchone()
    if not response:
        flash(f"Response with ID {response_id} not found.", "danger")
        return redirect(url_for('moderate.admin_uploaded_content_list'))
    query = text(f"SELECT challenge_name FROM challenge_submissions where id = :response_id")
    challenge = db_session.execute(query, {"response_id": response.challenge_id}).fetchone()

    if challenge is None:
        challenge = 'Challenge1'

    scan_results = scan_summary = None
    if response.virustotal_scan_results:
        scan_results = json.loads(response.virustotal_scan_results)
        if scan_results and 'data' in scan_results and 'attributes' in scan_results['data']:
             scan_summary = scan_results['data']['attributes'].get('stats', {})

    return render_template('admin_chall_details.html', 
                           response=response, 
                           challenge=challenge,
                           scan_results=scan_results, 
                           scan_summary=scan_summary)

@moderate_bp.route('/update-response-status/<string:response_id>/<string:action>', methods=['POST'])
@require_admin
def admin_update_response_status(response_id, action):
    response = db_session.get(ChallengeResponse, response_id)

    query = text("select points from user_points WHERE user_id = :user_id")
    user_points = db_session.execute(query, {"user_id": response.user_id}).scalar()

    query = text("SELECT points FROM challenge_submissions WHERE id = :challenge_id")
    points = db_session.execute(query, {"challenge_id": response.challenge_id}).scalar()
    if points:
        total_points= points + user_points
    else:
        total_points = user_points
    
    if not response:
        flash(f"Challenge response with ID {response_id} not found.", 'danger')
        return
    if not response:
        flash("Response not found.", "danger")
        return redirect(url_for('moderate.admin_uploaded_content_list'))

    if action == 'approve':
        query = text(f"UPDATE challenge_status SET status = 'APPROVED' WHERE challenge_id = {response.challenge_id}")
        db_session.execute(query)
        query = text("UPDATE user_points SET points = :points WHERE user_id = :user_id")
        db_session.execute(query, {'points': total_points, 'user_id': response.user_id})
        flash(f"Challenge response approved.", 'success')
    elif action == 'reject':
        query = text(f"UPDATE challenge_status SET status = 'REJECTED' WHERE challenge_id = {response.challenge_id}")
        db_session.execute(query)
        flash(f"Challenge response rejected.", 'warning')
    else:
        flash("Invalid action.", "danger")
    
    try:
        db_session.commit()
    except Exception as e:
        db_session.rollback()
        print(f"Database error: {e}", "danger")
    return redirect(url_for('moderate.admin_uploaded_content_list'))

@moderate_bp.route('/moderate-comments')
@require_admin
def admin_moderate_comments():
    comments_stmt = select(Comment).filter(or_(Comment.status == 'PENDING', Comment.status == 'REPORTED')).order_by(desc(Comment.timestamp))
    pending_comments = db_session.execute(comments_stmt).scalars().all()
    return render_template('admin_moderate.html', comments=pending_comments)

@moderate_bp.route('/update-comment-status/<string:comment_id>/<string:action>', methods=['POST'])
@require_admin
def admin_update_comment_status(comment_id, action):
    comment = db_session.get(Comment, comment_id)
    if not comment:
        flash("Comment not found.", "danger")
        return redirect(url_for('moderate.admin_moderate_comments'))

    if action == 'approve':
        comment.status = 'APPROVED'
        flash(f"Comment approved.", 'success')
    elif action == 'reject':
        comment.status = 'REJECTED'
        flash(f"Comment rejected.", 'warning')
    else:
        flash("Invalid action.", "danger")
    
    db_session.commit()
    return redirect(url_for('moderate.admin_moderate_comments'))
