from functools import wraps
from datetime import datetime, timedelta

import jwt
from flask import jsonify, make_response, request

from .errors import (AccessTokenNotExpiredError, InvalidAccessTokenError,
                     InvalidRefreshTokenError, TokenCompromisedError)

from .access_token import AccessToken
from .refresh_token import RefreshToken


class TokenSchema(object):

    def __init__(self,
                 refresh_token_cookie_name="refresh_token",
                 access_token_cookie_name="access_token",
                 access_token_duration=60,
                 refresh_token_duration=7,
                 secure_cookies_only=True):

        self.secure_cookies_only = secure_cookies_only
        self.refresh_token_cookie_name = refresh_token_cookie_name
        self.access_token_cookie_name = access_token_cookie_name
        self.compromised_tokens_error_callback = None
        self.after_new_access_token_generated_callback = None
        self.access_token = AccessToken()
        self.refresh_token = RefreshToken()
        self.access_token_duration = access_token_duration
        self.refresh_token_duration = refresh_token_duration

    def generate_access_token(self, refresh_token, access_token):
        """ Generates access token from refresh token

        :param refresh_token: refresh token
        :param access_token: access token
        """

        if not self.refresh_token.verify_refresh_token_callback(refresh_token):
            raise InvalidRefreshTokenError()

        try:
            refresh_token_compromised = self.refresh_token \
                .refresh_token_compromised_callback(refresh_token)
        except TypeError:
            refresh_token_compromised = self.refresh_token \
                .refresh_token_compromised_callback(
                    refresh_token, access_token)

        if refresh_token_compromised:
            raise TokenCompromisedError()

        jwt_claims = {}

        try:
            jwt_claims = self.access_token.decode_jwt_token(
                access_token, options={"verify_exp": False})
        except:
            raise InvalidAccessTokenError()

        if not AccessToken.access_token_expired(jwt_claims["exp"]):
            raise AccessTokenNotExpiredError()

        new_access_token = self.access_token.generate_jwt_token(
            jwt_claims["user_id"])

        if self.after_new_access_token_generated_callback is not None:
            self.after_new_access_token_generated_callback(
                refresh_token, new_access_token)

        return new_access_token

    def set_token_cookies(self, response, user_id, access_token_claims=None):
        """Sets session tokens (access and refresh) in cookies

        :param response: response object
        :param user_id: user user_id to attach to jwt
        """

        self.refresh_token.revoke_user_refresh_tokens_callback(user_id=user_id)

        access_token = self.access_token.generate_jwt_token(
            user_id, access_token_claims or {}, self.access_token_duration)
        
        if self.after_new_access_token_generated_callback is not None:
            self.after_new_access_token_generated_callback(access_token)

        refresh_token = self.refresh_token.create_refresh_token_callback(
            user_id, access_token)

        response.set_cookie(
            self.access_token_cookie_name,
            access_token,
            secure=self.secure_cookies_only,
            expires=datetime.utcnow() + self.access_token_duration + 5,
            httponly=True)
        response.set_cookie(
            self.refresh_token_cookie_name,
            refresh_token,
            expires=datetime.utcnow() + self.refresh_token_duration + 5,
            httponly=True,
            secure=self.secure_cookies_only)

    def tokens_required(self, f):
        """decorator for tokens required routes"""

        @wraps(f)
        def f_wrapper(*args, **kwargs):
            if self.access_token_cookie_name not in request.cookies:
                return jsonify({"message": "invalid credentials"}), 401

            access_token = request.cookies[self.access_token_cookie_name]

            try:
                self.access_token.decode_jwt_token(access_token)
            except jwt.ExpiredSignatureError:
                return jsonify({"message": "expired access token"}), 401
            except:
                return jsonify({"message": "invalid token"}), 401

            return f(*args, **kwargs)

        return f_wrapper

    def refresh_access_token(self, f):

        @wraps(f)
        def f_wrapper(*args, **kwargs):
            if not (self.refresh_token_cookie_name in request.cookies and
                    self.access_token_cookie_name in request.cookies):
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
                if self \
                .refresh_token \
                .invalid_access_token_error_callback is not None:
                    self.refresh_token.invalid_access_token_error_callback(
                        refresh_token, access_token)
                self.refresh_token.revoke_user_refresh_tokens_callback(
                    refresh_token=refresh_token)
                return jsonify({"message": "invalid token provided"}), 401
            except InvalidRefreshTokenError:
                if self \
                .refresh_token \
                .invalid_refresh_token_error_callback is not None:
                    self.refresh_token.invalid_refresh_token_error_callback(
                        refresh_token, access_token)
                return jsonify({"message": "invalid token provided"}), 401
            except TokenCompromisedError:
                if self.compromised_tokens_error_callback is not None:
                    self.compromised_tokens_error_callback(
                        refresh_token, access_token)
                self.refresh_token.revoke_user_refresh_tokens_callback(
                    refresh_token=refresh_token)
                return jsonify({"message": "compromised refresh token"}), 401
            except AccessTokenNotExpiredError:
                if self \
                .access_token \
                .access_token_not_expired_error_callback is not None:
                    self.access_token.access_token_not_expired_error_callback(
                        refresh_token, access_token)
                self.refresh_token.revoke_user_refresh_tokens_callback(
                    refresh_token=refresh_token)
                return jsonify({
                    "message": "user might be compromised, access revoked"
                }), 401

            f(*args, **kwargs)

            response = make_response(
                jsonify({
                    "message": "new access token generated"
                }))
            response.set_cookie(
                "access_token",
                new_access_token,
                secure=self.secure_cookies_only,
                httponly=True)

            return response

        return f_wrapper

    def compromised_tokens_error(self, f):
        self.compromised_tokens_error_callback = f
        return f

    def after_new_access_token_generated(self, f):
        self.after_new_access_token_generated_callback = f
        return f