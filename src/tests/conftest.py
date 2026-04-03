import pytest
from sqlalchemy import create_engine

from ..model import Base


@pytest.fixture
def conn(postgresql):
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
    Base.metadata.create_all(engine)

    with engine.connect() as conn:
        yield conn
