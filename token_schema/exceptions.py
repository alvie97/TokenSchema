class TokenSchemaException(Exception):
    """
    Base exceptions for all token_schema excpetions
    """
    pass

class InvalidRefreshTokenError(TokenSchemaException):
    """
    Error when refresh token is invalid
    """
    pass

class InvalidAccessTokenError(TokenSchemaException):
    """
    Error when refresh token is invalid
    """
    pass

class TokensCompromisedError(TokenSchemaException):
    """
    Base exception for compromised tokens
    """
    pass

class AccessTokenCompromisedError(TokensCompromisedError):
    """
    Error when the access token has been compromised
    """
    pass

class RefreshTokenCompromisedError(TokensCompromisedError):
    """
    Error when the refresh token has been compromised
    """
    pass

class RevokedTokenError(TokenSchemaException):
    """
    Error when a token has been revoked
    """
    pass

class AccessTokenNotExpiredError(TokenSchemaException):
    """
    Error when the access token is not expired. Used when trying to generate
    a new access token from refresh token and it is not expired
    """
    pass