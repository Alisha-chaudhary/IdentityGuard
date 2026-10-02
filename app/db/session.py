from collections.abc import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import DATABASE_URL

IN_MEMORY_URLS = ("sqlite://", "sqlite:///:memory:")


def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
    """SQLite ignores foreign keys unless enabled on every connection."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def make_engine(url: str) -> Engine:
    kwargs: dict = {}

    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}

        if url in IN_MEMORY_URLS:
            # One shared connection so an in-memory test DB isn't lost between calls.
            kwargs["poolclass"] = StaticPool

    engine = create_engine(url, **kwargs)

    if url.startswith("sqlite"):
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)

    return engine


engine = make_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    expire_on_commit=False,
)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, always closed."""
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()