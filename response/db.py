import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session, DeclarativeBase
import json

DATABASE_URL = os.environ.get('SQLALCHEMY_DATABASE_URI')
if not DATABASE_URL:
    raise ValueError("No DATABASE_URL set for SQLAlchemy in .env file")


engine = create_engine(DATABASE_URL)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


db_session = scoped_session(SessionLocal)


class Base(DeclarativeBase):
    pass

def init_db():
    Base.metadata.create_all(bind=engine)