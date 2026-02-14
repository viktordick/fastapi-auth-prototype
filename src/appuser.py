import hashlib
import os
from typing import List, Optional

from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import BigInteger


class Base(DeclarativeBase):
    pass


class AppUser(Base):
    __tablename__ = "appuser"
    id: Mapped[int] = mapped_column("appuser_id", BigInteger, primary_key=True)
    name: Mapped[str] = mapped_column("appuser_name")
    password: Mapped[Optional[str]] = mapped_column("appuser_password")

    logins: Mapped[List["AppUserLogin"]] = relationship(back_populates="user")

    def __repr__(self) -> str:
        return self.name

    @staticmethod
    def encrypt_pw(newpassword):
        # Generate a 16‑byte random salt
        salt = os.urandom(16)
        iterations = 100_000
        hash_bytes = hashlib.pbkdf2_hmac(
            "sha256", newpassword.encode(), salt, iterations
        )
        return f"{salt.hex()}|{iterations}|{hash_bytes.hex()}"

    def verify_pw(self, password):
        parts = self.password.split("|")
        salt = bytes.fromhex(parts[0])
        iterations = int(parts[1])
        stored_hash = bytes.fromhex(parts[2])
        hash_bytes = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return stored_hash == hash_bytes


class AppUserLogin(Base):
    __tablename__ = "appuserlogin"
    id: Mapped[int] = mapped_column("appuserlogin_id", BigInteger, primary_key=True)
    appuser_id: Mapped[int] = mapped_column(
        "appuserlogin_appuser_id", BigInteger, ForeignKey("appuser.appuser_id")
    )
    cookie: Mapped[str] = mapped_column("appuserlogin_cookie")
    nextcookie: Mapped[Optional[str]] = mapped_column("appuserlogin_nextcookie")
    done: Mapped[bool] = mapped_column("appuserlogin_done", default=False)
    user: Mapped["AppUser"] = relationship(back_populates="logins")

    def __repr__(self) -> str:
        return f"{self.user.name} ({self.id})"
