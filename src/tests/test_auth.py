from sqlalchemy import func, select

from ..model import (
    AppGroup,
    AppPerm,
    AppPermXGroup,
    AppPermXStc,
    AppStc,
    AppUser,
    AppUserXPerm,
    AppUserXStc,
)

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

    # Check roles for user - empty, but with status 200, so we are logged in
    client.cookies = dict(response.cookies)
    response = client.get("/roles")
    assert response.status_code == 200
    assert response.json() == []


def test_roles(client, session) -> None:
    """
    Set up a user that is assigned to two permission groups, but on two different
    organization areas. Check that the roles that are returned are computed correctly.
    """
    groups = [AppGroup(zoperole=name) for name in ["A", "B"]]
    session.add_all(groups)
    session.flush()
    user: AppUser = session.execute(
        select(AppUser).where(func.lower(AppUser.name) == func.lower("test"))
    ).scalar_one()
    root: AppStc = session.execute(
        select(AppStc).where(AppStc.parent_appstc_id.is_(None))
    ).scalar_one()
    appstc_ids = {}
    for name in ["A", "B"]:
        stc = AppStc(name=name, parent_appstc_id=root.id)
        group = AppGroup(zoperole=name)
        perm = AppPerm(name=name)
        session.add_all([stc, group, perm])
        session.flush()
        appstc_ids[name] = stc.id
        session.add_all(
            [
                AppUserXStc(appuser_id=user.id, appstc_id=stc.id),
                AppUserXPerm(appuser_id=user.id, appperm_id=perm.id),
                AppPermXGroup(appperm_id=perm.id, appgroup_id=group.id),
                AppPermXStc(appperm_id=perm.id, appstc_id=stc.id),
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
    for name, appstc_id in appstc_ids.items():
        assert client.get(f"/roles?__appstc_id={appstc_id}").json() == [name]

    # If calling without appstc_id, the one with the lower ID (since the depths
    # are equal) is chosen.
    assert client.get("/roles").json() == ["A"]
