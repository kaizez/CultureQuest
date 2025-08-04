import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session, DeclarativeBase
import json

from dotenv import load_dotenv

def load_env():
    """Load environment variables from .env file."""
    # Look for .env in the parent directory (main app directory)
    basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    dotenv_path = os.path.join(basedir, '.env')
    if os.path.exists(dotenv_path):
        print(f"[RESPONSE] Loading .env file from {dotenv_path}")
        load_dotenv(dotenv_path)
    else:
        print('[RESPONSE] Error finding .env file')

load_env()

# Build database URI from individual environment variables (same as main app)
# Always use individual components to match main app, ignore SQLALCHEMY_DATABASE_URI
db_host = os.environ.get('DB_HOST')
db_port = os.environ.get('DB_PORT')
db_user = os.environ.get('DB_USER')
db_password = os.environ.get('DB_PASSWORD')
db_name = os.environ.get('DB_NAME')

if all([db_host, db_port, db_user, db_password, db_name]):
    DATABASE_URL = f'mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
    print(f"[RESPONSE] Built database URL from components: {db_host}:{db_port}/{db_name}")
    print(f"[RESPONSE] Using database user: {db_user}")
else:
    print(f"[RESPONSE] Missing DB components - Host: {db_host}, Port: {db_port}, User: {db_user}, DB: {db_name}")
    raise ValueError("No DATABASE_URL or individual DB components set in .env file")

print(f"[RESPONSE] Final DATABASE_URL: {DATABASE_URL}")
engine = create_engine(DATABASE_URL)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


db_session = scoped_session(SessionLocal)


class Base(DeclarativeBase):
    pass

def init_db():
    Base.metadata.create_all(bind=engine)