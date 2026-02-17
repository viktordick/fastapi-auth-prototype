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
