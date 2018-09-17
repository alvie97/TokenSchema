from token_schema import create_access_token, encode_jwt
from datetime import timedelta


def test_tokens_required(app, client, tok_schema):
    with app.app_context():
        access_token = create_access_token("test")

    client.set_cookie(
        "localhost",
        app.config["ACCESS_COOKIE_NAME"],
        access_token,
        httponly=True)

    response = client.get("/")

    assert response.status_code == 200
    assert response.get_json() == "test"


def test_access_token_required_invalid_token(app, client, tok_schema):
    client.set_cookie(
        "localhost",
        app.config["ACCESS_COOKIE_NAME"],
        "invalid.access.token",
        httponly=True)

    response = client.get("/")

    assert response.status_code == 401
    assert response.get_json()["message"] == "invalid access token"


def test_access_token_required_expired_token(app, client, tok_schema):
    access_token = encode_jwt(app.config["JWT_SECRET"],
                              app.config["JWT_ALGORITHM"],
                              timedelta(seconds=-10), {"user_id": "test"})

    client.set_cookie(
        "localhost",
        app.config["ACCESS_COOKIE_NAME"],
        access_token,
        httponly=True)

    response = client.get("/")

    assert response.status_code == 401
    assert response.get_json()["message"] == "expired access token"


def test_access_token_required_no_token(app, client, tok_schema):
    response = client.get("/")

    assert response.status_code == 401
    assert response.get_json()["message"] == "access token not in cookies"
