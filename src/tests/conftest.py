import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from ..model import AppStc, AppUser, Base, View


@pytest.fixture
def session(postgresql):
    """
    Set up database session with matching schema and some basic data
    """
    url = (
        f"postgresql+psycopg://{postgresql.info.user}:"
        f"{postgresql.info.password}@"
        f"{postgresql.info.host}:"
        f"{postgresql.info.port}/"
        f"{postgresql.info.dbname}"
    )

    engine = create_engine(url)

    # Create tables for each test
    Base.metadata.create_all(engine)

    session = Session(engine)
    for view in View.__subclasses__():
        name = view.__tablename__
        defn = view.definition
        session.execute(text(f"create or replace view {name} as {defn}"))

    root = AppStc(name="root")
    session.add_all([root])
    session.flush()
    sub = AppStc(name="sub", parent_appstc_id=root.id)
    user = AppUser("test", "1234")
    session.add_all([sub, user])
    session.commit()
    yield session
    session.commit()
