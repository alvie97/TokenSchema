class RefreshToken(object):
    """ refresh token class """

    def __init__(self):
        self.verify_refresh_token_callback = None
        self.user_has_refresh_tokens_callback = None
        self.refresh_token_compromised_callback = None
        self.revoke_user_refresh_tokens_callback = None
        self.create_refresh_token_callback = None
        self.invalid_refresh_token_error_callback = None
    
    def verify_refresh_token(self, f):
        self.verify_refresh_token_callback = f
        return f

    def refresh_token_compromised(self, f):
        self.refresh_token_compromised_callback = f
        return f

    def invalid_refresh_token_error(self, f):
        self.invalid_refresh_token_error_callback = f
        return f

    def user_has_refresh_tokens(self, f):
        """check if user has any active refresh token
        :param user_id
        """
        self.user_has_refresh_tokens_callback = f
        return f

    def revoke_user_refresh_tokens(self, f):
        """ revoke all user refresh tokens
        
        function should have as params user_id="" and refresh_token=""
        to find user id associated with refresh_token if user_id is not
        provided
        """
        self.revoke_user_refresh_tokens_callback = f
        return f

    def create_refresh_token(self, f):
        self.create_refresh_token_callback = f
        return f
    
