from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), default='user')  # 'user' or 'admin'
    challenges = db.relationship('Challenge', backref='creator', lazy=True)
    submissions = db.relationship('Submission', backref='submitter', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def is_admin(self):
        return self.role == 'admin'

class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    reward = db.Column(db.String(120), nullable=False)
    xp = db.Column(db.Integer, nullable=False)
    criteria = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(16), default='pending') # pending/approved/closed
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    submissions = db.relationship('Submission', backref='challenge', lazy=True)
    admin_comments = db.relationship('AdminComment', backref='challenge', lazy=True)

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(16), default='pending') # pending/approved/rejected
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin_comments = db.relationship('AdminComment', backref='submission', lazy=True)

class AdminComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    challenge_id = db.Column(db.Integer, db.ForeignKey('challenge.id'), nullable=True)
    submission_id = db.Column(db.Integer, db.ForeignKey('submission.id'), nullable=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
