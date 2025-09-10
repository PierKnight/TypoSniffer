import os
from sqlalchemy.engine import URL
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from .tables import *

Session = None

def init_db():
    global Session

    if Session != None:
        raise RuntimeError("Database already initialized")
    
    DATABASE_URL = URL.create( 
        drivername = 'postgresql+psycopg2',
        username = os.environ.get('DB_USER', 'postgres'),
        password = os.environ.get('DB_PASSWORD', 'postgres'),
        host = os.environ.get('DB_HOST', 'erre'),
        port = os.environ.get('DB_PORT', '5432'),
        database = os.environ.get('DB_NAME', 'typosniffer')
    )

    engine = create_engine(DATABASE_URL, echo=True)

    Session = scoped_session(sessionmaker(bind=engine))
   
        

    


