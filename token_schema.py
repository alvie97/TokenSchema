from datetime import datetime, timedelta
from calendar import timegm
from functools import wraps

from errors import (InvalidAccessTokenError, InvalidRefreshTokenError,
                    TokenCompromisedError, AccessTokenNotExpiredError)

import jwt
from flask import request, jsonify, make_response


class TokenSchema(object):
    def __init__(self,
                 jwt_secret,
                 jwt_algorithm,
                 refresh_token_duration=60,
                 refresh_token_cookie_name="refresh_token",
                 access_token_cookie_name="access_token"):

        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.refresh_token_duration = refresh_token_duration
        self.refresh_token_cookie_name = refresh_token_cookie_name
        self.access_token_cookie_name = access_token_cookie_name
        self.verify_refresh_token_callback = None
        self.refresh_token_compromised_callback = None
        self.after_new_access_token_generated_callback = None
        self.invalid_access_token_error_callback = None
        self.invalid_refresh_token_error_callback = None
        self.compromised_tokens_error_callback = None
        self.access_token_not_expired_error_callback = None

    def generate_jwt_token(self, user_id, exp=60, **kwargs):
        """Generate a JWT token

        :param user_id: the user that will own the token
        :param exp: expiration time in seconds
        """

        return jwt.encode({
            "user_id": user_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=exp),
            **kwargs
        },
                          self.jwt_secret,
                          algorithm=self.jwt_algorithm).decode("utf-8")

    @staticmethod
    def access_token_expired(exp):
        """verify if token has expired

        :param exp: token expiration date NumericDate
        """
        return exp < timegm(datetime.utcnow().utctimetuple())

    def decode_jwt_token(self, token, options={}):
        """Decodes jwt Token

        :param token: token to verify
        """

        jwt_claims = jwt.decode(
            token,
            self.jwt_secret,
            options=options,
            algoritms=self.jwt_algorithm)

        return jwt_claims

    def verify_refresh_token(self, f):
        self.verify_refresh_token_callback = f
        return f

    def refresh_token_compromised(self, f):
        self.refresh_token_compromised_callback = f
        return f

    def after_new_access_token_generated(self, f):
        self.after_new_access_token_generated_callback = f
        return f

    def invalid_access_token_error(self, f):
        self.invalid_access_token_error_callback = f
        return f

    def invalid_refresh_token_error(self, f):
        self.invalid_refresh_token_error_callback = f
        return f

    def compromised_tokens_error(self, f):
        self.compromised_tokens_error_callback = f
        return f
    
    def access_token_not_expired_error(self, f):
        self.access_token_not_expired_error_callback = f
        return f

    def generate_access_token(self, refresh_token, access_token):
        """ Generates access token from refresh token

        :param refresh_token: refresh token
        :param access_token: access token
        """

        if self.verify_refresh_token_callback(refresh_token):
            raise InvalidRefreshTokenError()

        if self.refresh_token_compromised_callback(refresh_token,
                                                   access_token):
            raise TokenCompromisedError()

        jwt_claims = {}

        try:
            jwt_claims = self.decode_jwt_token(
                access_token, options={"verify_exp": False})
        except:
            raise InvalidAccessTokenError()

        if not self.access_token_expired(access_token):
            raise AccessTokenNotExpiredError()

        new_access_token = self.generate_jwt_token(jwt_claims["user_id"])

        if self.after_new_access_token_generated_callback is not None:
            self.after_new_access_token_generated_callback(
                refresh_token, new_access_token)

        return new_access_token

    def set_session_tokens(self, response, username):
        """Sets session tokens (access and refresh) in cookies

        :param response: response object
        :param username: user username to attach to jwt
        """

        if self.user_has_refresh_tokens_callback():
            self.revoke_user_refresh_tokens_callback(username)
            return

        access_token = self.generate_jwt_token(username)
        refresh_token = self.create_refresh_token_callback(access_token)

        response.set_cookie(
            self.access_token_cookie_name, access_token, httponly=True)
        response.set_cookie(
            self.refresh_token_cookie_name,
            refresh_token,
            expires=datetime.utcnow() + self.refresh_token_duration,
            httponly=True)

    def tokens_required(self, f):
        """decorator for tokens required routes"""

        @wraps(f)
        def f_wrapper(*args, **kwargs):
            if self.access_token_cookie_name not in request.cookies:
                return jsonify({"message": "invalid credentials"}), 401

            access_token = request.cookies["access_token"]

            try:
                self.decode_jwt_token(access_token)
            except jwt.ExpiredSignatureError:
                return jsonify({"message": "expired access token"}), 401
            except:
                return jsonify({"message": "invalid token"}), 401

            return f(*args, **kwargs)

        return f_wrapper

    def refresh_access_token(self, f):

        @wraps(f)
        def f_wrapper(*args, **kwargs):
            if not (self.refresh_token_cookie_name in request.cookies
                    and self.access_token_cookie_name in request.cookies):
                return jsonify({"message": "no tokens provided"}), 401

            access_token = request.cookies[self.access_token_cookie_name]
            refresh_token = request.cookies[self.refresh_token_cookie_name]

            if not (access_token and refresh_token):
                return jsonify({"message": "invalid tokens"}), 401

            new_access_token = ""

            try:
                new_access_token = self.generate_access_token(
                    refresh_token, access_token)
            except InvalidAccessTokenError:
                if self.invalid_access_token_error_callback is not None:
                    self.invalid_access_token_error_callback(
                        refresh_token, access_token)
                return jsonify({"message": "invalid token provided"}), 401
            except InvalidRefreshTokenError:
                if self.invalid_refresh_token_error_callback is not None:
                    self.invalid_refresh_token_error_callback(
                        refresh_token, access_token)
                return jsonify({"message": "invalid token provided"}), 401
            except TokenCompromisedError:
                if self.compromised_tokens_error_callback is not None:
                    self.compromised_tokens_error_callback(
                        refresh_token, access_token)
                return jsonify({"message": "compromised refresh token"}), 401
            except AccessTokenNotExpiredError:
                if self.access_token_not_expired_error_callback is not None:
                    self.access_token_not_expired_error_callback(
                        refresh_token, access_token)
                return jsonify({
                    "message":
                    "user might be compromised, access revoked"
                }), 401

            f(*args, **kwargs)

            response = make_response(
                jsonify({
                    "message": "new access token generated"
                }))
            response.set_cookie(
                "access_token", new_access_token, httponly=True)

            return response
        return f_wrapper