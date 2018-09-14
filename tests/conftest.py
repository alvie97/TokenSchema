import pytest
from flask import Flask
from token_schema import TokenSchema
from datetime import datetime, timedelta
from uuid import uuid4


@pytest.fixture
def app():

    app = Flask(__name__)

    yield app

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
    tok_schema = TokenSchema("secret", "HS256")

    def find_refresh_token(token):
        for tok in refresh_tokens:
            if tok["token"] == token:
                return tok

    @tok_schema.verify_refresh_token
    def verify_token(token):
        tok = find_refresh_token(token)
        return tok is not None and not (tok["expires_at"] < datetime.utcnow()
                                        or tok["revoked"])

    @tok_schema.refresh_token_compromised
    def refresh_token_compromised(refresh_token, access_token):
        tok = find_refresh_token(refresh_token)
        return tok["mapped_token"] != access_token

    @tok_schema.after_new_access_token_generated
    def after_new_access_token_generated(refresh_token, access_token):
        tok = find_refresh_token(refresh_token)

        tok["mapped_token"] = access_token

    @tok_schema.user_has_refresh_tokens
    def user_has_refresh_tokens(user_id):
        for token in refresh_tokens:
            if token["user_id"] == user_id:
                return True
        return False

    @tok_schema.revoke_user_refresh_tokens
    def revoke_user_refresh_tokens(user_id="", refresh_token=""):
        user = user_id
        if not user_id:
            tok = find_refresh_token(refresh_token)
            user = tok["user_id"]

        for token in refresh_tokens:
            if token["user_id"] == user and not token["revoked"]:
                token["revoked"] = True

    @tok_schema.create_refresh_token
    def create_refresh_token(user_id, access_token):
        token = str(uuid4())
        refresh_tokens.append({
            "token":
            token,
            "mapped_token":
            access_token,
            "user_id":
            user_id,
            "expires_at":
            datetime.utcnow() + timedelta(days=7),
            "revoked":
            False
        })

        return token

    @app.route("/token/refresh_access_token", methods=["POST"])
    @tok_schema.refresh_access_token
    def refresh_access_token():
        return ""
    
    return tok_schema