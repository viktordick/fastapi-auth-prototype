from typing import Optional

import argon2
from sqlmodel import Field, Relationship, SQLModel

DUMMY_HASH = argon2.PasswordHasher().hash(password="dummy")


class AppUser(SQLModel, table=True):
    appuser_id: Optional[int] = Field(default=None, primary_key=True)
    appuser_name: str
    appuser_password: Optional[str]

    def __init__(self, name: str, password: str):
        self.appuser_name = name
        self.appuser_password = self.encrypt_pw(password)

    @staticmethod
    def encrypt_pw(newpassword):
        return argon2.PasswordHasher().hash(password=newpassword)

    @staticmethod
    def verify_dummy(self, password):
        """
        Dummy verification to prevent timing attacks. If someone tries to log in and we
        don't find a matching user, we verify the password against a dummy hash, which
        takes about as much time as an actual verification.
        """
        try:
            argon2.PasswordHasher().verify(hash=DUMMY_HASH, password=password)
        except argon2.exceptions.VerifyMismatchError:
            pass

    def verify_pw(self, password):
        try:
            argon2.PasswordHasher().verify(
                hash=self.appuser_password,
                password=password,
            )
        except argon2.exceptions.VerifyMismatchError:
            return False
        return True


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
