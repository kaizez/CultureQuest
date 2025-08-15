import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session, DeclarativeBase
import json

db_host = os.environ.get('DB_HOST')
db_port = os.environ.get('DB_PORT')
db_user = os.environ.get('DB_USER')
db_password = os.environ.get('DB_PASSWORD')
db_name = os.environ.get('DB_NAME')
DATABASE_URL = f'mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}'
engine = create_engine(DATABASE_URL)


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


db_session = scoped_session(SessionLocal)


class Base(DeclarativeBase):
    pass

def init_db():
    Base.metadata.create_all(bind=engine)
