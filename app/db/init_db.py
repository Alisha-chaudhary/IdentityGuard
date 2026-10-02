from sqlalchemy.engine import Engine

from app.db import models  # noqa: F401  (importing registers the tables)
from app.db.base import Base
from app.db.session import engine as default_engine


def init_db(bind: Engine | None = None) -> None:
    Base.metadata.create_all(bind=bind or default_engine)