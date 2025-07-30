from db import db
from datetime import datetime
import uuid
from sqlalchemy.dialects.mysql import MEDIUMBLOB 

class ChallengeResponse(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    challenge_id = db.Column(db.String(36), db.ForeignKey('challenge.id'), nullable=False)
    # In a real multi-user app, this would be a ForeignKey to a User model
    user_id = db.Column(db.String(50), nullable=False, default='default_user') 
    
    reflection = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(255), nullable=True)
    file_content = db.Column(MEDIUMBLOB , nullable=True)
    submission_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # Status of the submission itself (e.g., pending scan, completed, failed)
    status = db.Column(db.String(50), nullable=False, default='PENDING_SCAN')
    mod_status = db.Column(db.String(50), nullable=False, default='PENDING')
    
    # Field to store VirusTotal scan results as a JSON string
    virustotal_scan_results = db.Column(db.Text, nullable=True)

    # Relationship to the parent Challenge
    challenge = db.relationship('Challenge', back_populates='responses')

    def __repr__(self):
        return f'<ChallengeResponse {self.id} for Challenge {self.challenge_id}>'

class Challenge(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)
    duration = db.Column(db.String(50), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), default='NEW') # e.g., 'NEW', 'IN PROGRESS', 'COMPLETED'
    progress_percent = db.Column(db.Integer, default=0)
    duration_left = db.Column(db.String(50), nullable=True)
    xp = db.Column(db.Integer, default=0)
    
    # JSON-encoded fields
    what_you_will_do = db.Column(db.Text, nullable=True)
    requirements = db.Column(db.Text, nullable=True)
    comments = db.Column(db.Text, nullable=True)
    
    responses = db.relationship('ChallengeResponse', back_populates='challenge', lazy=True)
    comments = db.relationship('Comment', backref='challenge', lazy='dynamic', cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Challenge {self.title}>'

class Comment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False, default='PENDING') # PENDING, APPROVED, REJECTED
    user_id = db.Column(db.String(50), nullable=False, default='default_user')
    challenge_id = db.Column(db.String(36), db.ForeignKey('challenge.id'), nullable=False)

    def __repr__(self):
        return f'<Comment {self.id}>'