"""
BountyOS - Database engine & session

SQLite is the local/default backend. Production deployments can set DATABASE_URL
for Postgres/Cloud SQL using psycopg, including Cloud SQL Unix socket URLs.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from urllib.parse import urlparse

from sqlmodel import SQLModel, Session, create_engine


def _env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def normalize_database_url(url: str | None = None) -> str:
    raw = url or os.getenv("DATABASE_URL", "sqlite:///./bountyos.db")
    if raw.startswith("postgresql://"):
        return raw.replace("postgresql://", "postgresql+psycopg://", 1)
    return raw


DATABASE_URL = normalize_database_url()
DATABASE_ECHO = _env_bool("DATABASE_ECHO")


def _engine_kwargs(url: str) -> dict:
    if url.startswith("sqlite"):
        return {"connect_args": {"check_same_thread": False}, "echo": DATABASE_ECHO}
    return {
        "pool_pre_ping": True,
        "pool_size": int(os.getenv("DATABASE_POOL_SIZE", "5")),
        "max_overflow": int(os.getenv("DATABASE_MAX_OVERFLOW", "10")),
        "echo": DATABASE_ECHO,
    }


engine = create_engine(DATABASE_URL, **_engine_kwargs(DATABASE_URL))


def database_health() -> dict:
    parsed = urlparse(DATABASE_URL)
    is_sqlite = DATABASE_URL.startswith("sqlite")
    return {
        "engine": "sqlite" if is_sqlite else "postgres",
        "url_configured": bool(os.getenv("DATABASE_URL")),
        "cloud_sql_socket": (not is_sqlite) and "/cloudsql/" in DATABASE_URL,
        "driver": parsed.scheme,
    }


def init_db():
    """Create all tables. Call once at startup after service model imports."""
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
