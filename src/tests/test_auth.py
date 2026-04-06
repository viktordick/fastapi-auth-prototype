from typing import Optional

from sqlalchemy import func, select

from ..model import AppGroup, AppPerm, AppPermXGroup, AppUser, AppUserXPerm

wrong_pw = "12345"
correct_pw = "1234"


def test_auth(client):
    """
    Check different login attempts
    """
    # Wrong password
    response = client.post(
        "/login",
        json={"username": "test", "password": wrong_pw},
        headers={"sec-fetch-site": "same-origin"},
    )
    assert response.status_code == 401
    assert "__user_cookie" not in response.cookies

    # Wrong sec-fetch-site
    response = client.post(
        "/login",
        json={"username": "test", "password": correct_pw},
        headers={"sec-fetch-site": "cross-origin"},
    )
    assert response.status_code == 401

    # Successful login
    response = client.post(
        "/login",
        json={"username": "test", "password": correct_pw},
        headers={"sec-fetch-site": "same-origin"},
    )
    assert response.status_code == 200
    assert "__user_cookie" in response.cookies

    # Check roles for user
    client.cookies = dict(response.cookies)
    response = client.get("/roles")
    assert response.status_code == 200


def test_roles(client, session):
    """
    Set up a user that is assigned to two permission groups, but on two different
    organization areas. Check that the roles that are returned are computed correctly.
    """
    groups = [AppGroup(zoperole=name) for name in ["A", "B"]]
    session.add_all(groups)
    stmt = select(AppUser).where(func.lower(AppUser.name) == func.lower("test"))
    user: Optional[AppUser] = None
    for user in session.execute(stmt).scalars():
        pass
    assert user is not None
    session.flush()
    for group in groups:
        perm = AppPerm(name=group.zoperole)
        session.add_all([perm])
        session.flush()
        session.add_all(
            [
                AppUserXPerm(appuser_id=user.id, appperm_id=perm.id),
                AppPermXGroup(appperm_id=perm.id, appgroup_id=group.id),
            ]
        )

    session.commit()

    client.cookies = dict(
        client.post(
            "/login",
            json={"username": "test", "password": correct_pw},
            headers={"sec-fetch-site": "same-origin"},
        ).cookies
    )
    resp = client.get("/roles")
    assert resp.json() == ["A", "B"]
