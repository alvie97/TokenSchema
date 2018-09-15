from datetime import datetime, timedelta
from helpers import get_cookie

from token_schema import create_access_token, decode_jwt
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