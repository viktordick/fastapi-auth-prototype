import os
from typing import Optional, Self

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


class AppUser(SQLModel, table=True):
    appuser_id: Optional[int] = Field(default=None, primary_key=True)
    appuser_name: str
    appuser_password: Optional[str]

    def __init__(self, name: str, password: str):
        self.appuser_name = name
        self.appuser_password = self.encrypt_pw(password)

    @classmethod
    def find(cls, session: Session, username: str, password: str) -> Optional[Self]:
        """
        Find the user with the given username and check its password. If there
        is a match, return the user.
        """
        stmt = select(cls).where(
            func.lower(AppUser.appuser_name) == func.lower(username)
        )
        user: Optional[Self] = session.exec(stmt).one_or_none()
        if not user or user.appuser_password is None:
            # Prevent timing attacks
            verify_hash(DUMMY_HASH, password)
            return None
        if verify_hash(user.appuser_password, password):
            return user
        return None

    @staticmethod
    def encrypt_pw(newpassword):
        return argon2.PasswordHasher().hash(password=newpassword)


class AppUserKey(SQLModel, table=True):
    appuserkey_id: Optional[int] = Field(default=None, primary_key=True)
    appuserkey_appuser_id: int = Field(foreign_key="appuser.appuser_id")
    appuserkey_key: str

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
            .where(
                func.regexp_match(AppUserKey.appuserkey_key, (ident + "-.*")).isnot(
                    None
                )
            )
            .where(AppUserKey.appuserkey_appuser_id == AppUser.appuser_id)
        )
        hasher = argon2.PasswordHasher()
        if not candidates:
            verify_hash(hash=DUMMY_HASH, password=key, hasher=hasher)
            return None
        for appuserkey, appuser in candidates:
            _, encrypted = appuserkey.appuserkey_key.split("-", 1)
            if verify_hash(hash=encrypted, password=key, hasher=hasher):
                return appuser
        return None


class AppUserLogin(SQLModel, table=True):
    appuserlogin_id: Optional[int] = Field(default=None, primary_key=True)
    appuserlogin_appuser_id: int = Field(foreign_key="appuser.appuser_id")
    appuserlogin_cookie: str
    appuserlogin_nextcookie: Optional[str]
    appuserlogin_done: bool = Field(default=False)
    user: "AppUser" = Relationship()


class AppGroup(SQLModel, table=True):
    appgroup_id: Optional[int] = Field(default=None, primary_key=True)
    appgroup_zoperole: str


class AppPerm(SQLModel, table=True):
    appperm_id: Optional[int] = Field(default=None, primary_key=True)
    appperm_name: str


class AppUserXPerm(SQLModel, table=True):
    appuserxperm_id: Optional[int] = Field(default=None, primary_key=True)
    appuserxperm_appuser_id: int = Field(foreign_key="appuser.appuser_id")
    appuserxperm_appperm_id: int = Field(foreign_key="appperm.appperm_id")
    user: "AppUser" = Relationship()
    perm: "AppPerm" = Relationship()


class AppPermXGroup(SQLModel, table=True):
    apppermxgroup_id: Optional[int] = Field(default=None, primary_key=True)
    apppermxgroup_appgroup_id: int = Field(foreign_key="appgroup.appgroup_id")
    apppermxgroup_appperm_id: int = Field(foreign_key="appperm.appperm_id")
    perm: "AppPerm" = Relationship()
    group: "AppGroup" = Relationship()
