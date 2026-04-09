import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import scoped_session, sessionmaker

from ..app import app
from ..dbsession import settings
from ..model import AppStc, AppUser, AppUserXStc, Base, View


@pytest.fixture
def connstr(postgresql):
    me = postgresql.info
    return (
        f"postgresql+psycopg://{me.user}:{me.password}@{me.host}:{me.port}/{me.dbname}"
    )


@pytest.fixture
def session(connstr):
    """
    Set up database session with matching schema and some basic data
    """
    engine = create_engine(connstr)

    # Create tables for each test
    Base.metadata.create_all(engine)

    SessionLocal = scoped_session(sessionmaker(bind=engine))
    session = SessionLocal()
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
    session.flush()
    session.add_all([AppUserXStc(appuser_id=user.id, appstc_id=root.id)])
    session.commit()
    yield session
    session.commit()
    SessionLocal.close()

    for view in View.__subclasses__():
        session.execute(text(f"drop view if exists {view.__tablename__} cascade"))
    session.commit()
    Base.metadata.drop_all(engine)


@pytest.fixture
def client(connstr, session):
    """
    Return a FastAPI test client. Patches the settings to use the correct connection
    string and no pooling, so when the database is teared down and built up between
    tests, we don't use any stale connections.
    """
    settings.connstr = connstr
    settings.pooling = False
    return TestClient(app)
