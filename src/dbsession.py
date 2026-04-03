import os
from typing import Annotated

from fastapi import Depends, Request, Response
from sqlalchemy import Connection, create_engine
from starlette.middleware.base import BaseHTTPMiddleware

engine = create_engine(
    "postgresql+psycopg://zope@/perfactema", echo=os.environ.get("SQL_DEBUG_ECHO")
)


class DBSessionMiddleware(BaseHTTPMiddleware):
    """
    Start a DB session for each request. Commit it at the end if there is no error,
    otherwise roll back and return a generic 500 error. Note that this does not mean
    that a request is not allowed to do its own commits in between.
    """

    async def dispatch(self, request, call_next):
        response = Response("Internal server error", status_code=500)
        try:
            request.state.db = engine.connect()
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


DBSession = Annotated[Connection, Depends(_get_session)]
