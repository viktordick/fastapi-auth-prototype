from typing import Optional

from fastapi import FastAPI, Request, Response, status
from pydantic import BaseModel
from sqlalchemy import func, not_, update

from .auth import COOKIE, Auth, SameSitePostMiddleware, require_roles
from .dbsession import DBSession, DBSessionMiddleware
from .model import AppUser, AppUserLogin

app = FastAPI()
app.add_middleware(DBSessionMiddleware)
app.add_middleware(SameSitePostMiddleware)


@app.put("/admin/generate_user")
@require_roles("Admin")
async def generate_user(username: str, password: str, session: DBSession):
    """
    Create a new user with the given username and password
    """
    user: AppUser = AppUser(username, password)
    session.add_all([user])


@app.post("/admin/rotate_cookies")
@require_roles("Admin")
async def rotate_cookies(session: DBSession):
    """
    Something that would usually rather be done periodically and can not be triggered
    manually.
    """
    session.execute(
        update(AppUserLogin)
        .where(not_(AppUserLogin.done))
        .values(nextcookie=func.uuidv4())
    )


class Credentials(BaseModel):
    """
    Username and password sent to /login
    """

    username: str
    password: str


@app.post("/login")
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


@app.get("/roles")
async def roles(user: Auth, response: Response) -> list[str]:
    """
    Return list of roles the user has. Returns Unauthorized if no user is found
    """
    if user is None:
        response.status_code = status.HTTP_401_UNAUTHORIZED
        return []
    return user.roles
