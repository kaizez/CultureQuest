from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_name = db.Column(db.String(255), nullable=True)  # Original filename
    file_url = db.Column(db.String(500), nullable=True)   # URL to access the file

    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'message': self.message,
            'timestamp': self.timestamp.strftime('%H:%M') if self.timestamp else '',
            'file_name': self.file_name,
            'file_url': self.file_url
        }