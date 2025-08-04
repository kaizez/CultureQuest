import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session, DeclarativeBase
import json

from dotenv import load_dotenv
def load_env():
    """Load environment variables from .env file."""
    basedir = os.path.abspath(os.path.dirname(__file__))
    dotenv_path = os.path.join(basedir, '.env')
    if os.path.exists(dotenv_path):
        print(f"Loading .env file from {dotenv_path}")
        load_dotenv(dotenv_path)
    else:
        print('Error finding .env file')

load_env()


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