from uuid import uuid4
from datetime import datetime, timedelta

from helpers import get_cookie


def test_refresh_token(client, tok_schema, refresh_tokens):
    access_token = tok_schema.generate_jwt_token("test", exp=-60)
    refresh_token = tok_schema.create_refresh_token_callback(
        "test", access_token)
    client.set_cookie("localhost", "access_token", access_token, httponly=True)
    client.set_cookie(
        "localhost", "refresh_token", refresh_token, httponly=True)
    response = client.post("/token/refresh_access_token")

    assert response.status_code == 200
    assert get_cookie(response, "access_token")


def test_revoked_refresh_token(client, tok_schema, refresh_tokens):
    access_token = tok_schema.generate_jwt_token("test")
    refresh_token = tok_schema.create_refresh_token_callback(
        "test", access_token)
    client.set_cookie("localhost", "access_token", access_token, httponly=True)
    client.set_cookie(
        "localhost", "refresh_token", refresh_token, httponly=True)

    refresh_tokens[0]["revoked"] = True
    response = client.post("/token/refresh_access_token")
    assert response.status_code == 401
    assert response.get_json()["message"] == "invalid token provided"


def test_compromised_refresh_token(tok_schema, client, refresh_tokens):

    # attacker request
    access_token = tok_schema.generate_jwt_token("test", expires_in=-60)
    refresh_token = tok_schema.create_refresh_token_callback(
        "test", access_token)
    client.set_cookie("localhost", "access_token", access_token, httponly=True)
    client.set_cookie(
        "localhost", "refresh_token", refresh_token, httponly=True)

    refresh_tokens[0]["mapped_token"] = tok_schema.generate_jwt_token(
        "test", expires_in=-60)

    response = client.post("/token/refresh_access_token")

    assert response.status_code == 401
    assert response.get_json()["message"] == "compromised refresh token"


# def test_invalid_token(app, client):
#     with app.app_context():
#         user = User(username="test", email="test@example.com", password="test")
#         db.session.add(user)
#         access_token = generate_token(user.username, expires_in=-60)
#         refresh_token = RefreshToken(
#             token=str(uuid4()),
#             user_id=user.username,
#             mapped_token=access_token,
#             expires_at=datetime.utcnow() - timedelta(seconds=60))
#         db.session.add(refresh_token)
#         db.session.commit()

#         refresh_token = refresh_token.token

#     csrf_token = generate_csrf_token()

#     client.set_cookie("localhost", "x-csrf-token", csrf_token, httponly=True)
#     client.set_cookie("localhost", "access_token", access_token, httponly=True)
#     client.set_cookie(
#         "localhost", "refresh_token", refresh_token, httponly=True)

#     response = client.post(
#         "/token/refresh_access_token", headers={"x-csrf-token": csrf_token})

#     assert response.status_code == 401
#     assert response.get_json()["message"] == "invalid token provided"

#     with app.app_context():
#         refresh_token = RefreshToken.first(token=refresh_token)
#         refresh_token.expires_at = datetime.utcnow() + timedelta(days=7)
#         db.session.commit()

#         refresh_token = refresh_token.token

#     csrf_token = generate_csrf_token()

#     client.set_cookie("localhost", "x-csrf-token", csrf_token, httponly=True)
#     client.set_cookie(
#         "localhost",
#         "access_token",
#         access_token[:int(len(access_token) / 2)],
#         httponly=True)
#     client.set_cookie(
#         "localhost", "refresh_token", refresh_token, httponly=True)

#     response = client.post(
#         "/token/refresh_access_token", headers={"x-csrf-token": csrf_token})

#     assert response.status_code == 401
#     assert response.get_json()["message"] == "invalid token provided"

# def test_expired_access_token(app, client):
#     with app.app_context():
#         user = User(username="test", email="test@example.com", password="test")
#         db.session.add(user)
#         access_token = generate_token(user.username, expires_in=-60)
#         refresh_token = RefreshToken(
#             token=str(uuid4()),
#             user_id=user.username,
#             mapped_token=access_token)
#         db.session.add(refresh_token)
#         db.session.commit()

#         refresh_token = refresh_token.token

#     csrf_token = generate_csrf_token()

#     client.set_cookie("localhost", "x-csrf-token", csrf_token, httponly=True)
#     client.set_cookie("localhost", "access_token", access_token, httponly=True)
#     client.set_cookie(
#         "localhost", "refresh_token", refresh_token, httponly=True)

#     response = client.get("/", headers={"x-csrf-token": csrf_token})
#     assert response.status_code == 401
#     assert response.get_json()["message"] == "expired access token"