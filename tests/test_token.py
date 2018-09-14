from datetime import datetime, timedelta
from helpers import get_cookie


def test_refresh_token(client, tok_schema):
    access_token = tok_schema.access_token.generate_jwt_token("test", exp=-60)
    refresh_token = tok_schema.refresh_token.create_refresh_token_callback(
        "test", access_token)
    client.set_cookie("localhost", "access_token", access_token, httponly=True)
    client.set_cookie(
        "localhost", "refresh_token", refresh_token, httponly=True)
    response = client.post("/token/refresh_access_token")

    assert response.status_code == 200
    assert get_cookie(response, "access_token")


def test_revoked_refresh_token(client, tok_schema, refresh_tokens):
    access_token = tok_schema.access_token.generate_jwt_token("test")
    refresh_token = tok_schema.refresh_token.create_refresh_token_callback(
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
    access_token = tok_schema.access_token.generate_jwt_token("test", exp=-60)
    refresh_token = tok_schema.refresh_token.create_refresh_token_callback(
        "test", access_token)
    client.set_cookie("localhost", "access_token", access_token, httponly=True)
    client.set_cookie(
        "localhost", "refresh_token", refresh_token, httponly=True)

    refresh_tokens[0][
        "mapped_token"] = tok_schema.access_token.generate_jwt_token(
            "test", exp=-60)

    response = client.post("/token/refresh_access_token")

    assert response.status_code == 401
    assert response.get_json()["message"] == "compromised refresh token"


def test_invalid_token(client, tok_schema, refresh_tokens):
    access_token = tok_schema.access_token.generate_jwt_token("test", exp=-60)
    refresh_token = tok_schema.refresh_token.create_refresh_token_callback(
        "test", access_token)
    client.set_cookie("localhost", "access_token", access_token, httponly=True)
    client.set_cookie(
        "localhost", "refresh_token", refresh_token, httponly=True)

    refresh_tokens[0]["expires_at"] = datetime.utcnow() - timedelta(seconds=60)

    response = client.post("/token/refresh_access_token")

    assert response.status_code == 401
    assert response.get_json()["message"] == "invalid token provided"

    refresh_tokens[0]["expires_at"] = datetime.utcnow() + timedelta(seconds=60)

    client.set_cookie(
        "localhost",
        "access_token",
        access_token[:int(len(access_token) / 2)],
        httponly=True)

    response = client.post("/token/refresh_access_token")

    assert response.status_code == 401
    assert response.get_json()["message"] == "compromised refresh token"


def test_tokens_required(client, tok_schema):

    access_token = tok_schema.access_token.generate_jwt_token("test", exp=-60)
    refresh_token = tok_schema.refresh_token.create_refresh_token_callback(
        "test", access_token)

    client.set_cookie("localhost", "access_token", access_token, httponly=True)
    client.set_cookie(
        "localhost", "refresh_token", refresh_token, httponly=True)

    response = client.get("/")
    assert response.status_code == 401
    assert response.get_json()["message"] == "expired access token"