from typing import Optional

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import func, not_, update

from .auth import (
    COOKIE,
    Auth,
    SameSitePostMiddleware,
    add_403_to_openapi,
    require_roles,
)
from .dbsession import DBSession, DBSessionMiddleware
from .model import AppUserLogin

app = FastAPI()
app.add_middleware(DBSessionMiddleware)
app.add_middleware(SameSitePostMiddleware)


class Credentials(BaseModel):
    """
    Username and password sent to /login
    """

    username: str
    password: str


@app.post(
    "/login",
    responses={
        200: {"model": bool, "description": "Login successful, cookie set"},
        401: {"model": bool, "description": "Login failed"},
    },
)
async def login(
    creds: Credentials,
    session: DBSession,
    response: Response,
    request: Request,
) -> bool:
    login: Optional[AppUserLogin] = AppUserLogin.login(
        session, creds.username, creds.password
    )
    if login is None:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return False
    response.set_cookie(
        key=COOKIE,
        value=login.cookie,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    return True


@app.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(response: Response) -> None:
    response.delete_cookie(COOKIE)


@app.get("/roles")
async def roles(user: Auth, response: Response) -> list[str]:
    """
    Return list of roles the user has. Returns Unauthorized if no user is found
    """
    if user is None:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return []
    return user.roles


@app.post("/admin/rotate_cookies", status_code=status.HTTP_204_NO_CONTENT)
@require_roles("Admin")
async def rotate_cookies(session: DBSession) -> None:
    """
    Something that would usually rather be done periodically and can not be triggered
    manually. Just to demonstrate require_roles.
    """
    session.execute(
        update(AppUserLogin)
        .where(not_(AppUserLogin.done))
        .values(nextcookie=func.uuidv4())
    )


add_403_to_openapi(app)
