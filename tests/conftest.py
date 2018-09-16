import pytest
from flask import Flask, make_response, jsonify, current_app
from token_schema import (TokenSchema, get_current_user, access_token_required,
                          set_token_cookies, get_access_token_from_cookie,
                          get_refresh_token_from_cookie,
                          InvalidAccessTokenError, InvalidRefreshTokenError)
from datetime import datetime, timedelta
from uuid import uuid4


@pytest.fixture
def app():

    app = Flask(__name__)
    app.config["JWT_SECRET"] = "secret-jwt-key"
    app.config["JWT_ALGORITHM"] = "HS256"
    app.config["SECURE_TOKEN_COOKIES"] = False

    return app


@pytest.fixture
def client(app):
    client = app.test_client()
    return client


@pytest.fixture
def refresh_tokens():
    refresh_tokens = []
    return refresh_tokens


@pytest.fixture
def tok_schema(app, refresh_tokens):

    with app.app_context():
        tok_schema = TokenSchema(app)

    def find_refresh_token(token):
        for tok in refresh_tokens:
            if tok["token"] == token:
                return tok

    @tok_schema.verify_refresh_token
    def verify_token(token):
        tok = find_refresh_token(token)
        return tok is not None and not (tok["expires_at"] < datetime.utcnow()
                                        or tok["revoked"])

    @tok_schema.compromised_tokens
    def compromised_tokens(refresh_token, access_token):
        tok = find_refresh_token(refresh_token)
        return tok["mapped_token"] != access_token

    @tok_schema.after_new_access_token_created
    def new_access_token_generated(access_token, refresh_token):
        tok = find_refresh_token(refresh_token)

        tok["mapped_token"] = access_token

    @tok_schema.revoke_user_refresh_tokens
    def revoke_user_refresh_tokens(user_id):
        for token in refresh_tokens:
            if token["user_id"] == user_id and not token["revoked"]:
                token["revoked"] = True

    @tok_schema.create_refresh_token
    def create_refresh_token(user_id, access_token):
        token = str(uuid4())
        refresh_tokens.append({
            "token": token,
            "mapped_token": access_token,
            "user_id": user_id,
            "expires_at": datetime.utcnow() + timedelta(days=30),
            "revoked": False
        })

        return token

    @app.route("/")
    @access_token_required
    def test_route():
        return jsonify(get_current_user())

    @app.route("/set_cookies")
    def set_cookies():
        response = make_response(jsonify("test"))
        set_token_cookies(response, "test")
        return response

    @app.route("/get_cookies")
    def get_cookies():
        try:
            access_token = get_access_token_from_cookie()
        except KeyError:
            return jsonify("{} cookie not set",
                           current_app.config["ACCESS_COOKIE_NAME"])
        except InvalidAccessTokenError as e:
            return jsonify(e.message)

        try:
            refresh_token = get_refresh_token_from_cookie()
        except KeyError:
            return jsonify("{} cookie not set",
                           current_app.config["REFRESH_COOKIE_NAME"])
        except InvalidRefreshTokenError as e:
            return jsonify(e.message)
        refresh_tokens = get_refresh_token_from_cookie()

        return jsonify(access_token, refresh_token)

    return tok_schema