from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

# MySQL table options
mysql_table_args = {
    'mysql_engine': 'InnoDB',
    'mysql_charset': 'utf8mb4',
    'mysql_collate': 'utf8mb4_unicode_ci'
}

class ChallengeSubmission(db.Model):
    __tablename__ = 'challenge_submissions'
    __table_args__ = mysql_table_args
    
    id = db.Column(db.Integer, primary_key=True)
    challenge_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    completion_criteria = db.Column(db.Text, nullable=False)
    media_filename = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(20), default='On Hold')  # 'On Hold', 'Approved', 'Rejected'
    comments = db.Column(db.Text, nullable=True)
    points = db.Column(db.Integer, nullable=True)  # Points awarded for the submission
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Legacy fields for backward compatibility
    name = db.Column(db.String(255), nullable=True)  # Can be null for new submissions
    email = db.Column(db.String(255), nullable=True)  # Can be null for new submissions  
    phone = db.Column(db.String(50), nullable=True)   # Can be null for new submissions
    
    def to_dict(self):
        return {
            'id': self.id,
            'challenge_name': self.challenge_name,
            'description': self.description,
            'completion_criteria': self.completion_criteria,  
            'media': self.media_filename,
            'status': self.status,
            'comments': self.comments,
            'points': self.points,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else '',
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else '',
            # Legacy fields for backward compatibility
            'name': self.name or self.challenge_name,
            'email': self.email or '',
            'phone': self.phone or ''
        }