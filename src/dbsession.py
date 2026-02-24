import os
from typing import Annotated

from fastapi import Depends, Request, Response
from perfact.dbschematools import patch
from sqlmodel import Session, create_engine
from starlette.middleware.base import BaseHTTPMiddleware

engine = create_engine(
    "postgresql+psycopg://zope@/perfactema", echo=os.environ.get("SQL_DEBUG_ECHO")
)
patch(f"{os.path.dirname(__file__)}/schema")


class DBSessionMiddleware(BaseHTTPMiddleware):
    """
    Start a DB session for each request. Commit it at the end if there is no error,
    otherwise roll back and return a generic 500 error. Note that this does not mean
    that a request is not allowed to do its own commits in between.
    """

    async def dispatch(self, request, call_next):
        response = Response("Internal server error", status_code=500)
        try:
            request.state.db = Session(engine)
            response = await call_next(request)
            request.state.db.commit()
        except Exception:
            request.state.db.rollback()
            raise
        finally:
            request.state.db.close()
        return response


def _get_session(request: Request):
    return request.state.db


DBSession = Annotated[Session, Depends(_get_session)]
