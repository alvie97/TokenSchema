from flask import current_app
from datetime import datetime, timedelta
from uuid import uuid4
import jwt

class JwtToken(object):
    """ base class for jwt tokens """
    def __init__(self):
        self.jwt_secret = current_app.config["JWT_SECRET_KEY"]
        self.jwt_algorithm = current_app.config["JWT_ALGORITHM"]

    def generate_jwt_token(self, user_id, claims=None, exp=60):
        """Generate a JWT token

        :param user_id: the user that will own the token
        :param exp: expiration time in seconds
        """
        jwt_claims = claims or {}
        return jwt.encode({
            "user_id": user_id,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=exp),
            "ref_id": str(uuid4()),
            **jwt_claims
        },
                          self.jwt_secret,
                          algorithm=self.jwt_algorithm).decode("utf-8")

    def decode_jwt_token(self, token, options=None):
        """Decodes jwt Token

        :param token: token to verify
        """

        jwt_claims = jwt.decode(
            token,
            self.jwt_secret,
            options=options or {},
            algoritms=[self.jwt_algorithm])

        return jwt_claims