from datetime import datetime, timedelta
from helpers import get_cookie

from token_schema import (
    create_access_token, decode_jwt, create_fresh_access_token,
    RefreshTokenCompromisedError, AccessTokenCompromisedError,
    InvalidAccessTokenError, InvalidRefreshTokenError, TokensCompromisedError)
from datetime import timedelta
from jwt import ExpiredSignatureError
import pytest

secret = "top-secret"
algorithm = "HS256"


def test_access_token():
    access_token = create_access_token("test", secret, algorithm,
                                       timedelta(seconds=10),
                                       {"test_claim": "test"})

    jwt_claims = decode_jwt(access_token, secret, algorithm)

    assert jwt_claims["user_id"] == "test"
    assert jwt_claims["test_claim"] == "test"
    assert "exp" in jwt_claims
    assert "jti" in jwt_claims
    assert "iat" in jwt_claims


def test_access_token_expired():
    access_token = create_access_token("test", secret, algorithm,
                                       timedelta(seconds=-10))

    with pytest.raises(ExpiredSignatureError):
        jwt_claims = decode_jwt(access_token, secret, algorithm)


def test_decode_jwt_options_parameter():
    access_token = create_access_token("test", secret, algorithm,
                                       timedelta(seconds=-10))

    jwt_claims = decode_jwt(
        access_token, secret, algorithm, options={"verify_exp": False})

    assert jwt_claims["user_id"] == "test"
    assert "exp" in jwt_claims
    assert "jti" in jwt_claims
    assert "iat" in jwt_claims


def test_create_fresh_access_token(app, tok_schema, refresh_tokens):
    access_token = create_access_token("test", app.config["JWT_SECRET"],
                                       app.config["JWT_ALGORITHM"],
                                       timedelta(seconds=-10))
    refresh_token = tok_schema.create_refresh_token_callback(
        "test", access_token)

    with app.app_context():
        new_access_token = create_fresh_access_token(refresh_token,
                                                     access_token)

    decode_jwt(new_access_token, app.config["JWT_SECRET"],
               app.config["JWT_ALGORITHM"])

    assert access_token != new_access_token
    assert refresh_tokens[0]["mapped_token"] == new_access_token


def test_create_fresh_access_token_with_non_expired_access_token(
        app, tok_schema):
    access_token = create_access_token("test", app.config["JWT_SECRET"],
                                       app.config["JWT_ALGORITHM"],
                                       timedelta(seconds=10))

    refresh_token = tok_schema.create_refresh_token_callback(
        "test", access_token)

    with app.app_context():
        new_access_token = create_fresh_access_token(refresh_token,
                                                     access_token)

    assert new_access_token == access_token


def test_compromised_refresh_token(app, tok_schema):
    invalid_access_token = "invalid.access.token"
    refresh_token = tok_schema.create_refresh_token_callback(
        "test", invalid_access_token)
    with pytest.raises(RefreshTokenCompromisedError):
        with app.app_context():
            create_fresh_access_token(refresh_token, invalid_access_token)


def test_compromised_access_token(app, tok_schema):
    access_token = create_access_token("test", app.config["JWT_SECRET"],
                                       app.config["JWT_ALGORITHM"],
                                       timedelta(seconds=10))
    invalid_refresh_token = "invalid-refresh-token"
    with pytest.raises(AccessTokenCompromisedError):
        with app.app_context():
            create_fresh_access_token(invalid_refresh_token, access_token)

    access_token = create_access_token("test", app.config["JWT_SECRET"],
                                       app.config["JWT_ALGORITHM"],
                                       timedelta(seconds=-10))
    invalid_refresh_token = "invalid-refresh-token"
    with pytest.raises(AccessTokenCompromisedError):
        with app.app_context():
            create_fresh_access_token(invalid_refresh_token, access_token)


def test_invalid_access_token(app, tok_schema):
    invalid_access_token = "invalid.access.token"
    invalid_refresh_token = "invalid-refresh-token"

    with pytest.raises(InvalidAccessTokenError):
        with app.app_context():
            create_fresh_access_token(invalid_refresh_token,
                                      invalid_access_token)
