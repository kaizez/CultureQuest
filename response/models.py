from db import Base
from datetime import datetime
import uuid
from sqlalchemy import Column, String, Text, Integer, DateTime, func, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import MEDIUMBLOB

# class Challenge(Base):
#     __tablename__ = 'challenge'
    
#     # Core Challenge Fields
#     id = Column(Integer, primary_key=True, autoincrement=True)
#     challenge_name = Column(String(255), nullable=False)
#     description = Column(Text, nullable=False)
#     completion_criteria = Column(Text, nullable=False)
#     points = Column(Integer, default=0)
    
#     # User-submitted fields
#     name = Column(String(255), nullable=True)
#     email = Column(String(255), nullable=True)
#     phone = Column(String(50), nullable=True)
#     media_filename = Column(String(255), nullable=True)
#     comments = Column(Text, nullable=True)
    
#     # Status and Timestamps
#     status = Column(String(20), default='Pending')
#     created_at = Column(DateTime, default=func.now())
#     updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
#     # Relationships
#     responses = relationship('ChallengeResponse', back_populates='challenge', cascade="all, delete-orphan")
#     comment_entries = relationship('Comment', backref='challenge', lazy='dynamic', cascade="all, delete-orphan")

#     def __repr__(self):
#         return f'<Challenge {self.challenge_name}>'

class ChallengeResponse(Base):
    __tablename__ = 'challenge_response'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    challenge_id = Column(Integer, nullable=False)
    user_id = Column(String(50), nullable=False, default='default_user')
    reflection = Column(Text, nullable=True)
    filename = Column(String(255), nullable=True)
    file_content = Column(MEDIUMBLOB, nullable=True)
    submission_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    status = Column(String(50), nullable=False, default='PENDING_SCAN')
    mod_status = Column(String(50), nullable=False, default='PENDING')
    virustotal_scan_results = Column(Text, nullable=True)

class Comment(Base):
    __tablename__ = 'comment'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    text = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    status = Column(String(50), nullable=False, default='PENDING')
    user_id = Column(String(50), nullable=False, default='default_user')
    challenge_id = Column(Integer, nullable=False)