from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    messages = db.relationship('Message', backref='room', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'is_active': self.is_active
        }

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_name = db.Column(db.String(255), nullable=True)
    file_url = db.Column(db.String(500), nullable=True)
    
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'message': self.message,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'file_name': self.file_name,
            'file_url': self.file_url,
            'room_id': self.room_id
        }
