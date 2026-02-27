import os
from typing import List, Optional, Self

import argon2
from sqlmodel import Field, Relationship, Session, SQLModel, func, select

DUMMY_HASH = argon2.PasswordHasher().hash(os.urandom(16).hex())


def verify_hash(
    hash: str, password: str, hasher: Optional[argon2.PasswordHasher] = None
) -> bool:
    if hasher is None:
        hasher = argon2.PasswordHasher()
    try:
        hasher.verify(hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False


def Col(colname, **kw):
    """
    Wrapper for field type with aliased column name on the DB
    """
    return Field(**kw, sa_column_kwargs={"name": colname})


class AppUser(SQLModel, table=True):
    id: Optional[int] = Col("appuser_id", default=None, primary_key=True)
    name: str = Col("appuser_name")
    password: Optional[str] = Col("appuser_password")

    def __init__(self, name: str, password: str):
        self.name = name
        self.password = self.encrypt_pw(password)

    @classmethod
    def find(cls, session: Session, username: str, password: str) -> Optional[Self]:
        """
        Find the user with the given username and check its password. If there
        is a match, return the user.
        """
        stmt = select(cls).where(func.lower(AppUser.name) == func.lower(username))
        user: Optional[Self] = session.exec(stmt).one_or_none()
        if not user or user.password is None:
            # Prevent timing attacks
            verify_hash(DUMMY_HASH, password)
            return None
        if verify_hash(user.password, password):
            return user
        return None

    @staticmethod
    def encrypt_pw(newpassword):
        return argon2.PasswordHasher().hash(password=newpassword)


class AppUserKey(SQLModel, table=True):
    id: Optional[int] = Col("appuserkey_id", default=None, primary_key=True)
    appuser_id: int = Col("appuserkey_appuser_id", foreign_key="appuser.appuser_id")
    key: str = Col("appuserkey_key")

    @staticmethod
    def find(session: Session, auth: str) -> Optional[AppUser]:
        """
        Split the auth header into ident and key.
        Find a key that, when split on the first "-", starts with the ident and
        contains a hasded value of the key afterwards.
        Returns the user name if something is found.
        Note regarding timing attacks: This will scale with the number of
        matches found under the given ident, but for zero matches it takes
        roughly the same time as for one match.
        """
        ident, key = auth.split("-", 1)
        candidates = session.exec(
            select(AppUserKey, AppUser)
            .where(func.regexp_match(AppUserKey.key, (ident + "-.*")).isnot(None))
            .where(AppUserKey.appuser_id == AppUser.id)
        )
        hasher = argon2.PasswordHasher()
        if not candidates:
            verify_hash(hash=DUMMY_HASH, password=key, hasher=hasher)
            return None
        for appuserkey, appuser in candidates:
            _, encrypted = appuserkey.key.split("-", 1)
            if verify_hash(hash=encrypted, password=key, hasher=hasher):
                return appuser
        return None


class AppUserLogin(SQLModel, table=True):
    id: Optional[int] = Col("appuserlogin_id", default=None, primary_key=True)
    appuser_id: int = Col("appuserlogin_appuser_id", foreign_key="appuser.appuser_id")
    cookie: str = Col("appuserlogin_cookie")
    nextcookie: Optional[str] = Col("appuserlogin_nextcookie")
    done: bool = Col("appuserlogin_done", default=False)
    user: "AppUser" = Relationship()


class AppGroup(SQLModel, table=True):
    id: Optional[int] = Col("appgroup_id", default=None, primary_key=True)
    zoperole: str = Col("appgroup_zoperole")


class AppPerm(SQLModel, table=True):
    id: Optional[int] = Col("appperm_id", default=None, primary_key=True)
    name: str = Col("appperm_name")


class AppUserXPerm(SQLModel, table=True):
    id: Optional[int] = Col("appuserxperm_id", default=None, primary_key=True)
    appuser_id: int = Col("appuserxperm_appuser_id", foreign_key="appuser.appuser_id")
    appperm_id: int = Col("appuserxperm_appperm_id", foreign_key="appperm.appperm_id")
    user: "AppUser" = Relationship()
    perm: "AppPerm" = Relationship()


class AppPermXGroup(SQLModel, table=True):
    id: Optional[int] = Col("apppermxgroup_id", default=None, primary_key=True)
    appgroup_id: int = Col(
        "apppermxgroup_appgroup_id", foreign_key="appgroup.appgroup_id"
    )
    appperm_id: int = Col("apppermxgroup_appperm_id", foreign_key="appperm.appperm_id")
    perm: "AppPerm" = Relationship()
    group: "AppGroup" = Relationship()


class AppStc(SQLModel, table=True):
    id: Optional[int] = Col("appstc_id", default=None, primary_key=True)
    name: str = Col("appstc_name")
    parent_appstc_id: Optional[int] = Col(
        "appstc_parent_appstc_id", foreign_key="appstc.appstc_id"
    )
    parent: Optional["AppStc"] = Relationship(
        back_populates="children", sa_relationship_kwargs={"remote_side": "AppStc.id"}
    )
    children: List["AppStc"] = Relationship(back_populates="parent")
