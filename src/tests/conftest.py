import pytest
from sqlmodel import Session, SQLModel, create_engine

from ..model import AppStc


@pytest.fixture
def session(postgresql):
    # postgresql is a dict-like object with connection info
    url = (
        f"postgresql+psycopg://{postgresql.info.user}:"
        f"{postgresql.info.password}@"
        f"{postgresql.info.host}:"
        f"{postgresql.info.port}/"
        f"{postgresql.info.dbname}"
    )

    engine = create_engine(url, echo=True)

    # Create tables for each test
    SQLModel.metadata.create_all(engine)

    session = Session(engine)
    root = AppStc(name="root")
    session.add(root)
    return session
