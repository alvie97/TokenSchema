from datetime import timedelta

from flask import current_app
from jwt import ExpiredSignatureError

from .exceptions import (AccessTokenNotExpiredError, InvalidAccessTokenError,
                         TokenCompromisedError)
from .tokens import create_access_token, decode_jwt


class TokenSchema(object):
    """
    Class that defines the settings and callbacks for the token schema
    """

    def __init__(self, app=None):
        """
        Creates TokenSchema instance. The flask app can be passed or set
        with the init_app method later.

        :param app: Flask app
        """
        self.create_refresh_token_callback = None
        self.verify_refresh_token_callback = None
        self.revoke_user_refresh_tokens_callback = None
        self.compromised_tokens_callback = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """
        Registers extension with flask app

        :param app: Flask app
        """

        if not hasattr(app, "extensions"):
            app.extensions = {}
        app.extensions["flask_token_schema"] = self

        self.set_default_configurations(app)
        self.set_error_handlers(app)

    @staticmethod
    def set_default_configurations(app):
        """
        Sets flask default configurations

        :param app: Flask app
        """

        app.config.setdefault("ACCESS_COOKIE_NAME", "access_token_cookie")
        app.config.setdefault("REFRESH_COOKIE_NAME", "refresh_token_cookie")
        app.config.setdefault("SECURE_TOKEN_COOKIES", False)
        app.config.setdefault("ACCESS_TOKEN_DURATION", timedelta(seconds=60))
        app.config.setdefault("REFRESH_TOKEN_DURATION", timedelta(days=30))
        app.config.setdefault("JWT_ALGORITHM", "HS256")
        app.config.setdefault("JWT_SECRET", None)

    def create_fresh_access_token(self, refresh_token, access_token):
        """
        Generates access token using refresh token. Access token is generated
        if all checks are passed.

        :param refresh_token: the refresh token used to generated a fresh
                              access token.
        :param access_token: expired access token used for validation
        """

        # validate access token and if access token is not expired, if it is
        # not expired return access token or handler
        access_token_claims = {}
        try:
            decode_jwt(access_token, current_app.config["JWT_SECRET"],
                       current_app.config["JWT_ALGORITHM"])

            return access_token
        except ExpiredSignatureError:
            access_token_claims = decode_jwt(
                access_token,
                current_app.config["JWT_SECRET"],
                current_app.config["JWT_ALGORITHM"],
                options={"verify_exp": False})
        except:
            # validate refresh token, if refresh token is valid but access
            # token is invalid, the refresh token has been compromised
            if not self.verify_refresh_token_callback(refresh_token):
                raise AccessTokenNotExpiredError

            raise TokenCompromisedError("Refresh token is compromised")

        if not self.verify_refresh_token_callback(refresh_token):
            raise InvalidAccessTokenError

        # check if refresh token is mapped to access token and run the
        # compromised_refresh_token_callback if defined
        if self.compromised_tokens_callback(refresh_token, access_token):
            raise TokenCompromisedError(
                "refresh token and access token compromised")
        # generate new access token
        new_access_token = create_access_token(
            access_token_claims["user_id"], current_app.config["JWT_SECRET"],
            current_app.config["JWT_ALGORITHM"],
            current_app.config["ACCESS_TOKEN_DURATION"])

        # run new_access_token_created_callback if defined
        if self.new_access_token_created_callback is not None:
            try:
                self.new_access_token_created_callback(new_access_token)
            except TypeError:
                self.new_access_token_created_callback(new_access_token,
                                                       refresh_token)

        # return new access_token
        return new_access_token

    def create_refresh_token(self, callback):
        """
        Sets callback to create refresh tokens. Returns the refresh token
        string.

        *Note*: Callback must return the new refresh token string
        """

        self.create_refresh_token_callback = callback
        return callback

    def verify_refresh_token(self, callback):
        """
        Sets callback for verifying if refresh token is valid.

        *Note*: Callback will be given the refresh token string and must return
        True if the refresh token is valid, False otherwise.
        """

        self.verify_refresh_token_callback = callback
        return callback

    def compromised_tokens(self, callback):
        """
        Sets callback that verifies if a token has been compromised.
        It is called when trying to create a new access token using the refresh
        token.

        *Note*: Callback will be given the refresh token and access token, and
        must return True if either is compromised False otherwise.
        """

        self.compromised_tokens_callback = callback
        return callback

    def revoke_user_refresh_tokens(self, callback):
        """
        Sets callback that revokes all active refresh tokens owned by the user.
        It is called if the refresh token has been compromised and before 
        setting a new refresh token.

        *Note*: Callback will be given the user identifier
        """

        self.revoke_user_refresh_tokens_callback = callback
        return callback
