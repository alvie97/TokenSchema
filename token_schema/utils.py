from functools import wraps

from flask import current_app, jsonify, request, _app_ctx_stack
from jwt import ExpiredSignatureError

from .exceptions import (InvalidAccessTokenError, InvalidRefreshTokenError)
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


def set_token_cookies(response, user_id, access_token_claims=None):
    """
    Sets tokens (access and refresh) in cookies

    :param response: response object
    :param user_id: user user_id to attach to jwt
    """
    tok_schema = get_token_schema()
    tok_schema.revoke_user_refresh_tokens_callback(user_id)

    access_token = create_access_token(
        user_id,
        current_app.config["JWT_SECRET"],
        current_app.config["JWT_ALGORITHM"],
        current_app.config["ACCESS_TOKEN_DURATION"],
        user_claims=access_token_claims)

    refresh_token = tok_schema.create_refresh_token_callback(
        user_id, access_token)

    if tok_schema.after_new_access_token_generated_callback is not None:
        try:
            tok_schema.after_new_access_token_generated_callback(access_token)
        except KeyError:
            tok_schema.after_new_access_token_generated_callback(
                access_token, refresh_token)

    response.set_cookie(
        current_app.config["ACCESS_COOKIE_NAME"],
        access_token,
        secure=current_app.config["SECURE_TOKEN_COOKIES"],
        expires=current_app.config["ACCESS_COOKIE_EXPIRATION"],
        httponly=True)
    response.set_cookie(
        current_app.config["REFRESH_COOKIE_NAME"],
        refresh_token,
        expires=current_app.config["REFRESH_COOKIE_EXPIRATION"],
        httponly=True,
        secure=current_app.config["SECURE_TOKEN_COOKIES"])


def get_refresh_token_from_cookie():
    """
    Gets refresh token from cookies
    """
    refresh_token = request.cookies[current_app.config["REFRESH_COOKIE_NAME"]]

    if not refresh_token:
        raise InvalidRefreshTokenError("Empty {} cookie".format(
            current_app.config["REFRESH_COOKIE_NAME"]))

    return refresh_token


def get_access_token_from_cookie():
    """
    Gets access token from cookie
    """

    access_token = request.cookies[current_app.config["ACCESS_COOKIE_NAME"]]

    if not access_token:
        raise InvalidAccessTokenError("Empty {} cookie".format(
            current_app.config["ACCESS_COOKIE_NAME"]))

    return access_token


def tokens_required(f):
    """
    Decorator for tokens required routes
    """

    @wraps(f)
    def f_wrapper(*args, **kwargs):

        try:
            access_token = get_access_token_from_cookie()
        except KeyError:
            return jsonify({"message": "access token not in cookies"}), 401
        except InvalidAccessTokenError as err:
            return jsonify({"message": err.message}), 401

        try:
            _app_ctx_stack.top.jwt_claims = decode_jwt(
                access_token, current_app.config["JWT_SECRET"],
                current_app.config["JWT_ALGORITHM"])

        except ExpiredSignatureError:
            return jsonify({"message": "expired access token"}), 401
        except:
            return jsonify({"message": "invalid token"}), 401

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