from .db import Base
from datetime import datetime
import uuid
from sqlalchemy import Column, String, Text, Integer, DateTime, func, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import MEDIUMBLOB

class ChallegeStatus(Base):
    __tablename__ = 'challenge_status'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    challenge_id = Column(Integer, nullable=False)
    user_id = Column(String(50), nullable=False, default='default_user')
    status = Column(String(50), nullable=False, default='NEW')

class ChallengeResponse(Base):
    __tablename__ = 'challenge_response'
    __table_args__ = {'extend_existing': True}
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
    __table_args__ = {'extend_existing': True}
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    text = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    status = Column(String(50), nullable=False, default='PENDING')
    user_id = Column(String(50), nullable=False, default='default_user')
    challenge_id = Column(Integer, nullable=False)
    challenge_name = Column(Integer, nullable=False)
    username = Column(Integer, nullable=False)