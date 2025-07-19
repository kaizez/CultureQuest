from flask import Blueprint, render_template, redirect, url_for, request, flash, abort
from flask_login import login_required, current_user
from app.models import Challenge, Submission, db
from datetime import datetime

challenges_bp = Blueprint('challenges', __name__, url_prefix='/challenges')

@challenges_bp.route('/')
def list_challenges():
    challenges = Challenge.query.filter(Challenge.status == 'approved').order_by(Challenge.deadline.desc()).all()
    return render_template('challenges/list.html', challenges=challenges)

@challenges_bp.route('/<int:challenge_id>')
def challenge_details(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    can_participate = current_user.is_authenticated and challenge.status == 'approved'
    return render_template('challenges/details.html', challenge=challenge, can_participate=can_participate)

@challenges_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_challenge():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        deadline = request.form['deadline']
        reward = request.form['reward']
        xp = request.form['xp']
        criteria = request.form['criteria']
        if not (title and description and deadline and reward and xp and criteria):
            flash("All fields are required.", "danger")
            return render_template('challenges/create.html')
        try:
            deadline_dt = datetime.strptime(deadline, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash("Invalid deadline format.", "danger")
            return render_template('challenges/create.html')
        challenge = Challenge(
            title=title, description=description, deadline=deadline_dt,
            reward=reward, xp=int(xp), criteria=criteria, creator_id=current_user.id
        )
        db.session.add(challenge)
        db.session.commit()
        flash('Challenge submitted for admin approval.', 'info')
        return redirect(url_for('challenges.list_challenges'))
    return render_template('challenges/create.html')

@challenges_bp.route('/<int:challenge_id>/submit', methods=['POST'])
@login_required
def submit_entry(challenge_id):
    challenge = Challenge.query.get_or_404(challenge_id)
    if challenge.status != 'approved':
        abort(403)
    content = request.form['content']
    if not content:
        flash('Submission content required.', 'danger')
        return redirect(url_for('challenges.challenge_details', challenge_id=challenge_id))
    submission = Submission(content=content, challenge_id=challenge_id, user_id=current_user.id)
    db.session.add(submission)
    db.session.commit()
    flash('Submission sent for review!', 'success')
    return redirect(url_for('challenges.challenge_details', challenge_id=challenge_id))
