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

class SecurityViolation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), nullable=False)
    violation_type = db.Column(db.String(20), nullable=False)  # 'url' or 'file'
    content = db.Column(db.Text, nullable=False)  # URL or filename
    message_content = db.Column(db.Text, nullable=True)  # Original message content
    detection_details = db.Column(db.Text, nullable=True)  # JSON string of scan results
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, handled, ignored
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'violation_type': self.violation_type,
            'content': self.content,
            'message_content': self.message_content,
            'detection_details': self.detection_details,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'status': self.status,
            'room_id': self.room_id
        }

class MutedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    muted_at = db.Column(db.DateTime, default=datetime.utcnow)
    muted_until = db.Column(db.DateTime, nullable=True)  # None for permanent mute
    reason = db.Column(db.Text, nullable=True)
    muted_by_admin = db.Column(db.String(50), default='Admin')
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_name': self.user_name,
            'room_id': self.room_id,
            'muted_at': self.muted_at.strftime('%Y-%m-%d %H:%M:%S') if self.muted_at else '',
            'muted_until': self.muted_until.strftime('%Y-%m-%d %H:%M:%S') if self.muted_until else None,
            'reason': self.reason,
            'muted_by_admin': self.muted_by_admin,
            'is_active': self.is_active
        }
    
    def is_muted(self):
        """Check if mute is still active"""
        if not self.is_active:
            return False
        if self.muted_until is None:  # Permanent mute
            return True
        return datetime.utcnow() < self.muted_until
