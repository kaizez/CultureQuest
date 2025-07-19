from flask import Blueprint, render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from functools import wraps
from app.models import Challenge, Submission, AdminComment, db

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    pending_challenges = Challenge.query.filter_by(status='pending').all()
    live_challenges = Challenge.query.filter_by(status='approved').all()
    closed_challenges = Challenge.query.filter_by(status='closed').all()
    pending_submissions = Submission.query.filter_by(status='pending').all()
    return render_template('admin/dashboard.html', 
        pending_challenges=pending_challenges,
        live_challenges=live_challenges,
        closed_challenges=closed_challenges,
        pending_submissions=pending_submissions
    )

@admin_bp.route('/challenge/<int:challenge_id>/approve')
@login_required
@admin_required
def approve_challenge(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    challenge.status = 'approved'
    db.session.commit()
    flash('Challenge approved.', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/challenge/<int:challenge_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_challenge(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    challenge.status = 'closed'
    db.session.commit()
    flash('Challenge rejected.', 'info')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/submission/<int:submission_id>/approve')
@login_required
@admin_required
def approve_submission(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    submission.status = 'approved'
    db.session.commit()
    flash('Submission approved!', 'success')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/submission/<int:submission_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_submission(submission_id):
    submission = Submission.query.get_or_404(submission_id)
    submission.status = 'rejected'
    db.session.commit()
    flash('Submission rejected.', 'info')
    return redirect(url_for('admin.dashboard'))

@admin_bp.route('/comment', methods=['POST'])
@login_required
@admin_required
def add_admin_comment():
    content = request.form['content']
    challenge_id = request.form.get('challenge_id')
    submission_id = request.form.get('submission_id')
    comment = AdminComment(
        content=content, 
        challenge_id=challenge_id if challenge_id else None,
        submission_id=submission_id if submission_id else None,
        admin_id=current_user.id
    )
    db.session.add(comment)
    db.session.commit()
    flash('Comment added.', 'success')
    return redirect(request.referrer or url_for('admin.dashboard'))
