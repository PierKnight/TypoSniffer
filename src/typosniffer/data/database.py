import os
from sqlalchemy.engine import URL
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from .tables import *


DATABASE_URL = URL.create( 
    drivername = 'postgresql+psycopg2',
    username = os.environ.get('DB_USER', 'postgres'),
    password = os.environ.get('DB_PASSWORD', 'postgres'),
    host = os.environ.get('DB_HOST', 'localhost'),
    port = os.environ.get('DB_PORT', '5432'),
    database = os.environ.get('DB_NAME', 'postgres')
)

class DB:
    _engine = None
    _session_factory = None

    @classmethod
    def get_session(cls):
        if cls._engine is None:
            cls._engine = create_engine(DATABASE_URL, echo=False)
            cls._session_factory = scoped_session(sessionmaker(bind=cls._engine))
            Base.metadata.create_all(cls._engine)
        return cls._session_factory()
    
    @classmethod
    def get_new_session(cls):
        engine = create_engine(DATABASE_URL, echo=True)
        factory = sessionmaker(bind=engine)
        return engine, factory



