from .jwt_token import JwtToken
from datetime import datetime
from calendar import timegm

class AccessToken(JwtToken):
    """ access token class """

    def __init__(self):
        super().__init__()
        self.invalid_access_token_error_callback = None
        self.access_token_not_expired_error_callback = None
    
    @staticmethod
    def access_token_expired(exp):
        """verify if token has expired

        :param exp: token expiration date NumericDate
        """
        return exp < timegm(datetime.utcnow().utctimetuple())

    def invalid_access_token_error(self, f):
        self.invalid_access_token_error_callback = f
        return f

    def access_token_not_expired_error(self, f):
        self.access_token_not_expired_error_callback = f
        return f

