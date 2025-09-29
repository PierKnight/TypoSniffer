from sqlalchemy import URL, create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

from typosniffer.config.config import get_config

from .tables import *



class DB:
    _engine = None
    _session_factory = None

    @classmethod
    def get_session(cls):
        if cls._engine is None:

            database_cfg = get_config().database

            DATABASE_URL = URL.create( 
                drivername = database_cfg.drivername,
                username = database_cfg.username,
                password = database_cfg.password,
                host = database_cfg.host,
                port = database_cfg.port,
                database = database_cfg.database
            )

            cls._engine = create_engine(DATABASE_URL, echo=False)
            cls._session_factory = scoped_session(sessionmaker(bind=cls._engine, expire_on_commit=False))
            Base.metadata.create_all(cls._engine)
        return cls._session_factory()



