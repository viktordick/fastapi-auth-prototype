from fastapi.testclient import TestClient

from ..app import app


def test_auth(session):
    """
    Check different login attempts
    """
    client = TestClient(app)

    # Wrong password
    pw = "12345"
    response = client.post(
        "/login",
        json={"username": "test", "password": pw},
        headers={"sec-fetch-site": "same-origin"},
    )
    assert response.status_code == 401
    assert "__user_cookie" not in response.cookies

    # Wrong sec-fetch-site
    pw = "1234"
    response = client.post(
        "/login",
        json={"username": "test", "password": pw},
        headers={"sec-fetch-site": "cross-origin"},
    )
    assert response.status_code == 401

    # Successful login
    pw = "1234"
    response = client.post(
        "/login",
        json={"username": "test", "password": pw},
        headers={"sec-fetch-site": "same-origin"},
    )
    assert response.status_code == 200
    assert "__user_cookie" in response.cookies

    # Check roles for user
    response = client.get("/roles", cookies=dict(response.cookies))
    assert response.status_code == 200
