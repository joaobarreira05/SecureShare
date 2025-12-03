from sqlmodel import SQLModel, create_engine, Session
from .settings import settings

# check_same_thread=False is needed only for SQLite
connect_args = {"check_same_thread": False}

engine = create_engine(settings.DATABASE_URL, connect_args=connect_args)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session
