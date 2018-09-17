from functools import wraps
from datetime import datetime

from flask import current_app, jsonify, request, _app_ctx_stack
from jwt import ExpiredSignatureError, PyJWTError

from .exceptions import (InvalidAccessTokenError, InvalidRefreshTokenError,
                         AccessTokenCompromisedError,
                         RefreshTokenCompromisedError, TokensCompromisedError)
from .tokens import create_access_token, decode_jwt


def get_token_schema():
    """
    Gets the token schema from flask's app
    """

    try:
        return current_app.extensions["flask_token_schema"]
    except KeyError:
        raise RuntimeError("TokenSchema must be initialized "
                           "with the flask app")


def create_fresh_access_token(refresh_token, access_token):
    """
    Generates access token using refresh token. Access token is generated
    if all checks are passed.

    :param refresh_token: the refresh token used to generated a fresh
                            access token.
    :param access_token: expired access token used for validation
    """

    tok_schema = get_token_schema()

    # validate access token and if access token is not expired, if it is
    # not expired return access token or handler
    access_token_claims = {}
    try:
        decode_jwt(access_token, current_app.config["JWT_SECRET"],
                   current_app.config["JWT_ALGORITHM"])

        if not tok_schema.verify_refresh_token_callback(refresh_token):
            raise AccessTokenCompromisedError

        return access_token
    except ExpiredSignatureError:
        access_token_claims = decode_jwt(
            access_token,
            current_app.config["JWT_SECRET"],
            current_app.config["JWT_ALGORITHM"],
            options={"verify_exp": False})
    except AccessTokenCompromisedError:
        raise
    except PyJWTError:
        # validate refresh token, if refresh token is valid but access
        # token is invalid, the refresh token has been compromised
        if tok_schema.verify_refresh_token_callback(refresh_token):
            raise RefreshTokenCompromisedError

        raise InvalidAccessTokenError

    if not tok_schema.verify_refresh_token_callback(refresh_token):
        raise AccessTokenCompromisedError

    # run the compromised_refresh_token_callback
    if tok_schema.compromised_tokens_callback(refresh_token, access_token):
        raise TokensCompromisedError(
            "refresh token and access token compromised")

    # generate new access token
    new_access_token = create_access_token(access_token_claims["user_id"])

    # run new_access_token_created_callback if defined
    if tok_schema.after_new_access_token_created_callback is not None:
        try:
            tok_schema.after_new_access_token_created_callback(
                new_access_token)
        except TypeError:
            tok_schema.after_new_access_token_created_callback(
                new_access_token, refresh_token)

    # return new access_token
    return new_access_token


def set_token_cookies(response, user_id, access_token_claims=None):
    """
    Sets tokens (access and refresh) in cookies

    :param response: response object
    :param user_id: user user_id to attach to jwt
    """
    tok_schema = get_token_schema()
    tok_schema.revoke_user_refresh_tokens_callback(user_id)

    access_token = create_access_token(
        user_id, user_claims=access_token_claims)

    refresh_token = tok_schema.create_refresh_token_callback(
        user_id, access_token)

    if tok_schema.after_new_access_token_created_callback is not None:
        try:
            tok_schema.after_new_access_token_created_callback(access_token)
        except TypeError:
            tok_schema.after_new_access_token_created_callback(
                access_token, refresh_token)

    now = datetime.utcnow()

    response.set_cookie(
        current_app.config["ACCESS_COOKIE_NAME"],
        access_token,
        secure=current_app.config["SECURE_TOKEN_COOKIES"],
        expires=now + current_app.config["ACCESS_COOKIE_EXPIRATION"],
        httponly=True)
    response.set_cookie(
        current_app.config["REFRESH_COOKIE_NAME"],
        refresh_token,
        expires=now + current_app.config["REFRESH_COOKIE_EXPIRATION"],
        httponly=True,
        secure=current_app.config["SECURE_TOKEN_COOKIES"])


def get_refresh_token_from_cookie():
    """
    Gets refresh token from cookies
    """
    refresh_token = request.cookies[current_app.config["REFRESH_COOKIE_NAME"]]

    return refresh_token


def get_access_token_from_cookie():
    """
    Gets access token from cookie
    """

    access_token = request.cookies[current_app.config["ACCESS_COOKIE_NAME"]]

    return access_token


def access_token_required(f):
    """
    Decorator for tokens required routes
    """

    @wraps(f)
    def f_wrapper(*args, **kwargs):

        try:
            access_token = get_access_token_from_cookie()
        except KeyError:
            return jsonify({"message": "access token not in cookies"}), 401

        try:
            _app_ctx_stack.top.jwt_claims = decode_jwt(
                access_token, current_app.config["JWT_SECRET"],
                current_app.config["JWT_ALGORITHM"])

        except ExpiredSignatureError:
            return jsonify({"message": "expired access token"}), 401
        except PyJWTError:
            return jsonify({"message": "invalid access token"}), 401

        return f(*args, **kwargs)

    return f_wrapper


def get_current_user():
    """
    Gets the current user after the access token is decoded
    """

    jwt_claims = getattr(_app_ctx_stack.top, "jwt_claims", None)

    if jwt_claims is not None:
        return jwt_claims["user_id"]

    return None