"""
BountyOS - Database engine & session
"""

from sqlmodel import SQLModel, create_engine, Session
from contextlib import contextmanager
import os

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./bountyos.db")

# SQLite needs check_same_thread=False; ignored by Postgres
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)


def init_db():
    """Create all tables. Call once at startup."""
    SQLModel.metadata.create_all(engine)


def get_session():
    """FastAPI dependency — yields a DB session."""
    with Session(engine) as session:
        yield session


@contextmanager
def session_ctx():
    """Context manager for use outside FastAPI (agents, background tasks)."""
    with Session(engine) as session:
        yield session
