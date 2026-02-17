from typing import Optional

import argon2
from sqlmodel import Field, Relationship, SQLModel


class AppUser(SQLModel, table=True):
    appuser_id: Optional[int] = Field(default=None, primary_key=True)
    appuser_name: str
    appuser_password: Optional[str]

    @staticmethod
    def encrypt_pw(newpassword):
        return argon2.PasswordHasher().hash(password=newpassword)

    def verify_pw(self, password):
        return argon2.PasswordHasher().verify(
            hash=self.appuser_password,
            password=password,
        )


class AppUserLogin(SQLModel, table=True):
    appuserlogin_id: Optional[int] = Field(default=None, primary_key=True)
    appuserlogin_appuser_id: int = Field(foreign_key="appuser.appuser_id")
    appuserlogin_cookie: str
    appuserlogin_nextcookie: Optional[str]
    appuserlogin_done: bool = Field(default=False)
    user: "AppUser" = Relationship()
