# TokenSchema

This module defines a token auth schema for APIs made with flask.
The schema uses two tokens for authentication and authorization, an access
token, used to access protected endpoints and a refresh token, used
to generate new access tokens.

#### Access Token

This token should be short-lived, it defaults to 60 seconds. In this schema
a jwt token is used, having as claims issued at (iat), expiration date (exp),
user id (user_id) and a reference id (ref_id) generated with uuid4. This token
is used to access protected endpoints.

#### Refresh Token

This token can be long-lived, it defaults to 7 days. How this token is handled
is mostly set up by you. This token is used to generate new access tokens
once they expire.
