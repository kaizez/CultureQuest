from datetime import datetime
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared_db import db

# MySQL table options
mysql_table_args = {
    'mysql_engine': 'InnoDB',
    'mysql_charset': 'utf8mb4',
    'mysql_collate': 'utf8mb4_unicode_ci'
}

class ChatRoom(db.Model):
    __table_args__ = mysql_table_args
    
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

class UploadedFile(db.Model):
    __table_args__ = mysql_table_args
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    scan_info = db.Column(db.Text, nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'filename': self.filename,
            'original_filename': self.original_filename,
            'file_size': self.file_size,
            'mime_type': self.mime_type,
            'uploaded_at': self.uploaded_at.strftime('%Y-%m-%d %H:%M:%S') if self.uploaded_at else '',
            'scan_info': self.scan_info
        }

class Message(db.Model):
    __table_args__ = mysql_table_args
    
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(50), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_id = db.Column(db.Integer, db.ForeignKey('uploaded_file.id'), nullable=True)
    
    room_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    
    # Relationship to uploaded file
    uploaded_file = db.relationship('UploadedFile', backref='messages')

    def to_dict(self):
        file_info = None
        if self.uploaded_file:
            file_info = {
                'id': self.uploaded_file.id,
                'filename': self.uploaded_file.original_filename,
                'file_size': self.uploaded_file.file_size,
                'mime_type': self.uploaded_file.mime_type
            }
        
        return {
            'id': self.id,
            'user_name': self.user_name,
            'message': self.message,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S') if self.timestamp else '',
            'file_info': file_info,
            'room_id': self.room_id
        }

class SecurityViolation(db.Model):
    __table_args__ = mysql_table_args
    
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
    __table_args__ = mysql_table_args
    
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

class UserPoints(db.Model):
    __table_args__ = mysql_table_args
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    points = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'points': self.points,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else '',
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else ''
        }

class RewardItem(db.Model):
    __table_args__ = mysql_table_args
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    cost = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)
    image_url = db.Column(db.String(255), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    redemptions = db.relationship('RewardRedemption', backref='reward_item', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'cost': self.cost,
            'stock': self.stock,
            'image_url': self.image_url,
            'is_active': self.is_active,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else '',
            'updated_at': self.updated_at.strftime('%Y-%m-%d %H:%M:%S') if self.updated_at else ''
        }

class RewardRedemption(db.Model):
    __table_args__ = mysql_table_args
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    reward_item_id = db.Column(db.Integer, db.ForeignKey('reward_item.id'), nullable=False)
    points_spent = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, completed, cancelled
    redeemed_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'reward_item_id': self.reward_item_id,
            'points_spent': self.points_spent,
            'status': self.status,
            'redeemed_at': self.redeemed_at.strftime('%Y-%m-%d %H:%M:%S') if self.redeemed_at else ''
        }
