from typing import List, Optional

from perfact.generic import secret_check, secret_encrypt
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
        return secret_encrypt(newpassword, salt=True)

    def verify_pw(self, password):
        return secret_check(encrypted=self.password, secret=password)


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
