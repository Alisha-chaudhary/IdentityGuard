import pytest
from sqlalchemy.orm import sessionmaker

from app.auth.routes import _login_rate_limiter
from app.db import models  # noqa: F401
from app.db.base import Base
from app.db.session import make_engine


@pytest.fixture(autouse=True)
def _reset_login_rate_limiter():
    """The login rate limiter is module-level shared state; reset it between
    tests so one test's login attempts cannot rate-limit another."""
    _login_rate_limiter.reset()
    yield
    _login_rate_limiter.reset()


@pytest.fixture()
def db():
    """A fresh, empty in-memory database for every test."""
    engine = make_engine("sqlite://")
    Base.metadata.create_all(engine)

    session = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )()

    try:
        yield session
    finally:
        session.close()
        engine.dispose()