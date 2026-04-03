import os
from typing import Optional, Self

import argon2
from sqlalchemy import Connection, ForeignKey, func, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    relationship,
)
from sqlalchemy.orm import mapped_column as col

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


class Base(DeclarativeBase):
    pass


class AppUser(Base):
    __tablename__ = "appuser"
    id: Mapped[int] = col("appuser_id", primary_key=True)
    name: Mapped[str] = col("appuser_name")
    password: Mapped[Optional[str]] = col("appuser_password")

    def __init__(self, name: str, password: str):
        self.name = name
        self.password = self.encrypt_pw(password)

    @classmethod
    def find(cls, conn: Connection, username: str, password: str) -> Optional[Self]:
        """
        Find the user with the given username and check its password. If there
        is a match, return the user.
        """
        stmt = select(cls).where(func.lower(AppUser.name) == func.lower(username))
        user: Optional[Self] = conn.exec(stmt).one_or_none()
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


class AppUserKey(Base):
    __tablename__ = "appuserkey"
    id: Mapped[int] = col("appuserkey_id", primary_key=True)
    appuser_id: Mapped[int] = col(
        "appuserkey_appuser_id", ForeignKey("appuser.appuser_id")
    )
    key: Mapped[str] = col("appuserkey_key")
    appuser: Mapped[AppUser] = relationship()

    @staticmethod
    def find(conn: Connection, auth: str) -> Optional[AppUser]:
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
        candidates = conn.exec(
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


class AppUserLogin(Base):
    __tablename__ = "appuserlogin"
    id: Mapped[int] = col("appuserlogin_id", primary_key=True)
    appuser_id: Mapped[int] = col(
        "appuserlogin_appuser_id", foreign_key="appuser.appuser_id"
    )
    cookie: Mapped[str] = col("appuserlogin_cookie")
    nextcookie: Mapped[Optional[str]] = col("appuserlogin_nextcookie")
    done: Mapped[bool] = col("appuserlogin_done", default=False)
    user: Mapped[AppUser] = relationship()


class AppGroup(Base):
    __tablename__ = "appgroup"
    id: Mapped[int] = col("appgroup_id", primary_key=True)
    zoperole: Mapped[str] = col("appgroup_zoperole")


class AppPerm(Base):
    __tablename__ = "appperm"
    id: Mapped[int] = col("appperm_id", primary_key=True)
    name: Mapped[str] = col("appperm_name")


class AppUserXPerm(Base):
    __tablename__ = "appuserxperm"
    id: Mapped[int] = col("appuserxperm_id", primary_key=True)
    appuser_id: Mapped[int] = col(
        "appuserxperm_appuser_id", ForeignKey("appuser.appuser_id")
    )
    appperm_id: Mapped[int] = col(
        "appuserxperm_appperm_id", ForeignKey("appperm.appperm_id")
    )
    user: Mapped[AppUser] = relationship()
    perm: Mapped[AppPerm] = relationship()


class AppPermXGroup(Base):
    __tablename__ = "apppermxgroup"
    id: Mapped[int] = col("apppermxgroup_id", primary_key=True)
    appgroup_id: Mapped[int] = col(
        "apppermxgroup_appgroup_id", ForeignKey("appgroup.appgroup_id")
    )
    appperm_id: Mapped[int] = col(
        "apppermxgroup_appperm_id", ForeignKey("appperm.appperm_id")
    )
    perm: Mapped[AppPerm] = relationship()
    group: Mapped[AppGroup] = relationship()


class AppStc(Base):
    __tablename__ = "appstc"
    id: Mapped[int] = col("appstc_id", primary_key=True)
    name: Mapped[str] = col("appstc_name")
    parent_appstc_id: Mapped[Optional[int]] = col(
        "appstc_parent_appstc_id", ForeignKey("appstc.appstc_id")
    )
