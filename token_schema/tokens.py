from datetime import datetime, timedelta
from uuid import uuid4

import jwt
from flask import current_app


def encode_jwt(secret, algorithm, duration, additional_claims=None):
    """
    encodes (utf-8) JWT

    :param secret: key used to sign the token.
    :param algorithm: algorithm to sign the token.
    :param duration: time until the token expires. Parameter is a timedelta
    :param additional_claims: any other claims to provide to the token.
    """
    jti = str(uuid4())
    now = datetime.utcnow()

    claims = {"iat": now, "exp": now + duration, "jti": jti}

    if additional_claims is not None:
        claims.update(additional_claims)

    return jwt.encode(claims, secret, algorithm=algorithm).decode("utf-8")


def decode_jwt(token, secret, algorithm, options=None):
    """
    Decodes JWT and validates if its valid

    :param token: JWT to decode
    :param secret: secret used to verify signature
    :param algorithm: algorithm used to sign JWT
    """
    if options is not None:
        return jwt.decode(
            token, secret, algorithms=[algorithm], options=options)

    return jwt.decode(token, secret, algorithms=[algorithm])


def create_access_token(user_id, user_claims=None):
    """
    Creates access token

    :param user_id: id of user who owns this token. can be any identifier like
                    a username, email, uuid, etc.
    :param user_claims: additional claims to encode in jwt.
    """

    jwt_claims = {"user_id": user_id}

    if user_claims is not None:
        jwt_claims.update(user_claims)

    return encode_jwt(current_app.config["JWT_SECRET"],
                      current_app.config["JWT_ALGORITHM"],
                      current_app.config["ACCESS_TOKEN_DURATION"], jwt_claims)
