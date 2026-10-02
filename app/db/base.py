from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """All models inherit from this; it collects table definitions."""