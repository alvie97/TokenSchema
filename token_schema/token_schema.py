from datetime import timedelta

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
        self.after_new_access_token_created_callback = None

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

    @staticmethod
    def set_default_configurations(app):
        """
        Sets flask default configurations

        :param app: Flask app
        """

        app.config.setdefault("ACCESS_COOKIE_NAME", "access_token")
        app.config.setdefault("REFRESH_COOKIE_NAME", "refresh_token")
        app.config.setdefault("SECURE_TOKEN_COOKIES", True)
        app.config.setdefault("ACCESS_COOKIE_EXPIRATION",
                              timedelta(seconds=70))
        app.config.setdefault("REFRESH_COOKIE_EXPIRATION", timedelta(days=31))
        app.config.setdefault("ACCESS_TOKEN_DURATION", timedelta(seconds=60))
        app.config.setdefault("JWT_ALGORITHM", "HS256")
        app.config.setdefault("JWT_SECRET", None)

    def create_refresh_token(self, callback):
        """
        Sets callback to create refresh tokens. Returns the refresh token
        string.

        *Note*: Callback will be given the user identifier and access token
                string, and must return the new refresh token string
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

    def after_new_access_token_created(self, callback):
        """
        Sets callback that runs after a new access token is created

        *Note*: Callback will be given the new access token, if defined the
                refresh token will also be given
        """
        self.after_new_access_token_created_callback = callback
        return callback