import os
import uuid
from datetime import datetime
from typing import Optional, Self

import argon2
from sqlalchemy import BigInteger, DateTime, ForeignKey, String, func, select
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    relationship,
)
from sqlalchemy.orm import mapped_column as col
from sqlalchemy.types import ARRAY, Integer

from .dbsession import DBSession

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
    """
    Base class for table mappings. Allows declaring fields without their table prefix,
    the subclass hook will automatically rewrite them.
    """

    type_annotation_map = {str: String(), int: BigInteger()}

    id: Mapped[int] = col(primary_key=True)
    createtime: Mapped[datetime] = col(
        DateTime(timezone=True), server_default=func.now()
    )
    modtime: Mapped[datetime] = col(DateTime(timezone=True), server_default=func.now())
    creator: Mapped[Optional[str]] = col(server_default=func.db_username())
    author: Mapped[Optional[str]] = col(server_default=func.db_username())

    def __init_subclass__(cls, **kw):
        """
        Automatically add __tablename__ and prefix mapped columns with table name
        """
        # 1. Ensure tablename exists before mapping
        if "__tablename__" not in cls.__dict__:
            cls.__tablename__ = cls.__name__.lower()

        # 2. Let SQLAlchemy build the mapper, table, columns, etc.
        super().__init_subclass__(**kw)

        # 3. Now we have cls.__table__ and real Column objects. Adjust these so they
        # map to the prefixed column names on the database
        if hasattr(cls, "__table__"):
            prefix = cls.__tablename__ + "_"

            for col in cls.__table__.columns:
                # Only touch columns that still use their key as name
                # (i.e., no explicit name was given)
                if col.name == col.key:
                    new_name = prefix + col.key
                    col.name = new_name
                    col.key = new_name  # keep ORM key in sync


class View(DeclarativeBase):
    """
    Separate base for view definitions, so they are not created as tables but
    can be used like tables
    """

    type_annotation_map = {str: String(), int: BigInteger()}


class AppUser(Base):
    name: Mapped[str]
    password: Mapped[Optional[str]]

    def __init__(self, name: str, password: str):
        self.name = name
        self.password = self.encrypt_pw(password)

    @staticmethod
    def encrypt_pw(newpassword):
        return argon2.PasswordHasher().hash(password=newpassword)


class AppUserKey(Base):
    appuser_id: Mapped[int] = col(ForeignKey(AppUser.id))
    key: Mapped[str]
    appuser: Mapped[AppUser] = relationship()

    @staticmethod
    def find(session: DBSession, auth: str) -> Optional[AppUser]:
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
        candidates = session.execute(
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
    appuser_id: Mapped[int] = col(ForeignKey(AppUser.id))
    cookie: Mapped[Optional[str]]
    nextcookie: Mapped[Optional[str]]
    done: Mapped[bool] = col(default=False)
    user: Mapped[AppUser] = relationship()

    @classmethod
    def login(cls, session: DBSession, username: str, password: str) -> Optional[Self]:
        """
        Find the user with the given username and check its password. If there
        is a match, create a login and return it.
        """
        stmt = select(AppUser).where(func.lower(AppUser.name) == func.lower(username))
        user: Optional[AppUser] = None
        for user in session.execute(stmt).scalars():
            pass
        if not user or user.password is None:
            # Prevent timing attacks
            verify_hash(DUMMY_HASH, password)
            return None
        if not verify_hash(user.password, password):
            return None

        login = cls(appuser_id=user.id, cookie=uuid.uuid4())
        session.add_all([login])
        return login


class AppGroup(Base):
    zoperole: Mapped[str]


class AppPerm(Base):
    name: Mapped[str]


class AppUserXPerm(Base):
    appuser_id: Mapped[int] = col(ForeignKey(AppUser.id))
    appperm_id: Mapped[int] = col(ForeignKey(AppPerm.id))
    user: Mapped[AppUser] = relationship()
    perm: Mapped[AppPerm] = relationship()


class AppPermXGroup(Base):
    appgroup_id: Mapped[int] = col(ForeignKey(AppGroup.id))
    appperm_id: Mapped[int] = col(ForeignKey(AppPerm.id))
    perm: Mapped[AppPerm] = relationship()
    group: Mapped[AppGroup] = relationship()


class AppStc(Base):
    name: Mapped[str]
    parent_appstc_id: Mapped[Optional[int]] = col(ForeignKey("appstc.id"))


class AppUserXStc(Base):
    appuser_id: Mapped[int] = col(ForeignKey(AppUser.id))
    appstc_id: Mapped[int] = col(ForeignKey(AppStc.id))

    user: Mapped[AppUser] = relationship()
    stc: Mapped[AppStc] = relationship()


class AppPermXStc(Base):
    appperm_id: Mapped[int] = col(ForeignKey(AppPerm.id))
    appstc_id: Mapped[int] = col(ForeignKey(AppStc.id))

    perm: Mapped[AppPerm] = relationship()
    stc: Mapped[AppStc] = relationship()


class AppStc_Paths(View):
    __tablename__ = "appstc_paths"
    id: Mapped[int] = col("id", primary_key=True)
    id_path = col("id_path", ARRAY(Integer, as_tuple=True, zero_indexes=True))
    depth: Mapped[int] = col("depth")
    # This is a simplified definition, the actual one does not use a recursive
    # view, but a cached table so it can use indices. It also has some more
    # columns, but these are the only ones we need.
    definition = """
        with recursive tree as (
          select
            appstc_id as id,
            array[appstc_id] as id_path,
            1 as depth
          from appstc
          where appstc_parent_appstc_id is null
          union all
          select
            appstc_id,
            id_path || array[appstc_id],
            depth + 1
          from appstc
          join tree
            on id = appstc_parent_appstc_id
        )
        select * from tree
    """
