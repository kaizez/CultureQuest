from .db import Base
from datetime import datetime
import uuid
from sqlalchemy import Column, String, Text, Integer, DateTime, func, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.mysql import MEDIUMBLOB

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