from flask import Blueprint, render_template, redirect, url_for, flash, Response, current_app
import json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from utils import *
from db import db
import threading
from models import ChallengeResponse, Comment
from sqlalchemy import or_

moderate_bp = Blueprint('moderate', __name__, template_folder='templates')

limiter = Limiter(
    app=current_app,
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)


@moderate_bp.route('/download-file/<string:response_id>')
def download_file(response_id):
    response_record = db.session.get(ChallengeResponse, response_id)
    if not response_record or not response_record.file_content:
        flash("File not found.", "danger")
        return redirect(url_for('moderate.admin_uploaded_content_list'))
    
    return Response(
        response_record.file_content,
        mimetype='application/octet-stream',
        headers={"Content-Disposition": f"attachment;filename={response_record.filename}"}
    )

@moderate_bp.route('/rescan-file/<string:response_id>', methods=['POST'])
@limiter.limit("5 per minute")
def admin_rescan_file(response_id):
    response = db.session.get(ChallengeResponse, response_id)
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
def admin_uploaded_content_list():
    responses = ChallengeResponse.query.order_by(ChallengeResponse.submission_date.desc()).all()
    return render_template('admin_chall.html', responses=responses)

@moderate_bp.route('/uploaded-content/<string:response_id>')
def admin_uploaded_content_detail(response_id):
    response = db.session.get(ChallengeResponse, response_id)
    if not response:
        flash(f"Response with ID {response_id} not found.", "danger")
        return redirect(url_for('moderate.admin_uploaded_content_list'))

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

@moderate_bp.route('/update-response-status/<string:response_id>/<string:action>', methods=['POST'])
def admin_update_response_status(response_id, action):
    response = db.session.get(ChallengeResponse, response_id)
    if not response:
        flash("Response not found.", "danger")
        return redirect(url_for('moderate.admin_uploaded_content_list'))

    if action == 'approve':
        response.mod_status = 'APPROVED'
        flash(f"Challenge response approved.", 'success')
    elif action == 'reject':
        response.mod_status = 'REJECTED'
        flash(f"Challenge response rejected.", 'warning')
    else:
        flash("Invalid action.", "danger")
    
    db.session.commit()
    return redirect(url_for('moderate.admin_uploaded_content_list'))

@moderate_bp.route('/moderate-comments')
def admin_moderate_comments():
    pending_comments = Comment.query.filter(or_(Comment.status == 'PENDING', Comment.status == 'REPORTED')
    ).order_by(Comment.timestamp.desc()).all()
    return render_template('admin_moderate.html', comments=pending_comments)

@moderate_bp.route('/update-comment-status/<string:comment_id>/<string:action>', methods=['POST'])
def admin_update_comment_status(comment_id, action):
    comment = db.session.get(Comment, comment_id)
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
    
    db.session.commit()
    return redirect(url_for('moderate.admin_moderate_comments'))
