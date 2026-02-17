import uuid

from fastapi import FastAPI, Response
from sqlmodel import func, not_, select, update

from .auth import COOKIE, Auth, User, require_roles
from .dbsession import DBSession, DBSessionMiddleware
from .model import AppUser, AppUserLogin

app = FastAPI()
app.add_middleware(DBSessionMiddleware)


@app.put("/admin/generate_user")
@require_roles("Admin")
async def generate_user(username: str, password: str, session: DBSession):
    """
    We would not actually allow this, at least not without first checking elevated
    permissions
    """
    user: AppUser = AppUser(
        appuser_name=username,
        appuser_password=AppUser.encrypt_pw(password),
    )
    session.add(user)
    return {"success": True}


@app.post("/admin/rotate_cookies")
async def rotate_cookies(session: DBSession):
    """
    Something that would usually rather be done periodically and can not be triggered
    manually.
    """
    session.execute(
        update(AppUserLogin)
        .where(not_(AppUserLogin.appuserlogin_done))
        .values(appuserlogin_nextcookie=func.uuidv4())
    )


@app.post("/login")
async def login(username: str, password: str, session: DBSession, response: Response):
    stmt = select(AppUser).where(AppUser.appuser_name == username)
    user: AppUser = session.exec(stmt).one_or_none()
    if not user or not user.verify_pw(password):
        return {"success": False}
    login = AppUserLogin(
        appuserlogin_appuser_id=user.appuser_id,
        appuserlogin_cookie=uuid.uuid4(),
    )
    session.add(login)
    response.set_cookie(
        key=COOKIE,
        value=login.appuserlogin_cookie,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    return {
        "success": True,
    }


@app.post("/logout")
async def logout(session: DBSession, auth: Auth, response: Response) -> None:
    stmt = select(AppUserLogin).where(
        AppUserLogin.appuserlogin_id == auth.appuserlogin_id
    )
    login: AppUserLogin = session.scalars(stmt).one_or_none()
    if login:
        login.appuserlogin_done = True
    response.delete_cookie(COOKIE)


@app.get("/me")
async def me(session: DBSession, user: Auth) -> User:
    return user
