# Token-Auth

This is modules defines a token auth schema for APIs made with flask.
The schema uses two tokens for authentication and authorization, an access
token, used to authenticate and authorized the user and a refresh token, used
to generate new access tokens.

#### Access Token

This token should be short-lived, it defaults to 60 seconds. In this schema
a jwt token is used, having as claims issued at (iat), expiration date (exp),
user id (user_id) and a reference id (ref_id) generated with uuid4. This token
is use for authorization, where an endpoint can be accessed until the token
expires.

#### Refresh Token

This token can be long-lived, it defaults to 7 days. How this token is handled
is mostly set up by you. This token is used to generate new access tokens
once they expire, this is done with the decorator `refresh_access_token` which
wraps around an endpoint function in flask.

## Set up

To use the module you have to instantiate a _TokenSchema_ class object which has
a few arguments.

`refresh_token_cookie_name="refresh_token"`
defines a the name to be used for the refresh token cookie.
`access_token_cookie_name="access_token"`
defines a the name to be used for the access token cookie.
`access_token_duration=60`
defines the duration of the access token until it expires in seconds
`refresh_token_duration=7`
defines the duration of the refresh token until it expires in days
`secure_cookies_only=True`
If the secure flag should be set

**Note**: the httponly flag is set for all cookies

After the class is instatiated some callback have to be defined

`verify_refresh_token(refresh_token)`

Verifies if refresh token is valid, refresh token is pass as an argument

```python
refresh_token_compromised(refresh_token)
refresh_token_compromised(refresh_token, access_token)
```

Verifies if the refresh token has been compromised, the refresh token is passed,
if the access token is needed it can also be passed

`revoke_user_refresh_tokens(user_id="", refresh_token="")`

Revokes all user's valid refresh tokens. It is call with the user id 
`user_id=user_id` before setting token cookies so that it doesn't exist more 
than one valid refresh tokens, this will be useful in the case that the refresh
token has been compromised and the user was loggged out without the token being 
revoked. It is also called when generating a new access token from the 
`refresh_access_token` endpoint wrapper if the refresh token has been 
compromised, in this case the refresh token is passed 
`refresh_token=refresh_token`.

`create_refresh_token(user_id, access_token)`

Creates refresh token, user id and access token are passed. Should return the
access token.

Additionally some callback can be defined:

`invalid_refresh_token_error_callback`

Called when the refresh token is invalid when trying to create a new access 
token in the `refresh_access_token` endpoint wrapper.

`invalid_access_token_error_callback`

Called when the access token is invalid when trying to create a new access 
token in the `refresh_access_token` endpoint wrapper.

`access_token_not_expired_error_callback` 

Called if the access token is not expired and you're trying to generate a new 
access token from `refresh_access_token` endpoint wrapper.

`after_new_access_token_generated_callback(access_token)`

It is called after the new access token is generated, the access token is 
passed.

For the jwt encode and decode to work the `JWT_SECRET_KEY` and `JWT_ALGORITHM`
app configurations should be set.

## Usage

A few functions and decorators are defined that you can use to handle the 
auth.

`set_token_cookies(self, response, user_id, access_token_claims=None)`

You can use this function to set the access token and refresh token cookies.

`token_required`

This decorator wraps around an endpoint and checks if the access token is valid
and sends a 401 response code and a message in case it isn't.

`refresh_access_token`

This decorator wraps around the endpoint used to generate a new access token. 
It checks if the refresh token is valid and has not been compromised, then if 
the access token is valid and has expired, and finally generates the new access 
token. After the new access token is generated the `new_access_token_generated` 
callback is called, then the wrapped function is called and a response is 
generated setting the access token cookie with the new access token.

### Example

```python

from flask import Flask
from token_auth import TokenSchema

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "secre-jwt-key"
app.config["JWT_ALGORITHM"] = "HS256"

refresh_tokens = []

tok_schema = TokenSchema(secure_cookies_only=False)

def find_refresh_token(token):
    for tok in refresh_tokens:
        if tok["token"] == token:
            return tok

@tok_schema.refresh_token.verify_refresh_token
def verify_token(token):
    tok = find_refresh_token(token)
    return tok is not None and not (tok["expires_at"] < datetime.utcnow()
                                    or tok["revoked"])

@tok_schema.refresh_token.refresh_token_compromised
def refresh_token_compromised(refresh_token, access_token):
    tok = find_refresh_token(refresh_token)
    return tok["mapped_token"] != access_token

@tok_schema.after_new_access_token_generated
def after_new_access_token_generated(refresh_token, access_token):
    tok = find_refresh_token(refresh_token)

    tok["mapped_token"] = access_token

@tok_schema.refresh_token.user_has_refresh_tokens
def user_has_refresh_tokens(user_id):
    for token in refresh_tokens:
        if token["user_id"] == user_id:
            return True
    return False

@tok_schema.refresh_token.revoke_user_refresh_tokens
def revoke_user_refresh_tokens(user_id="", refresh_token=""):
    user = user_id
    if not user_id:
        tok = find_refresh_token(refresh_token)
        user = tok["user_id"]

    for token in refresh_tokens:
        if token["user_id"] == user and not token["revoked"]:
            token["revoked"] = True

@tok_schema.refresh_token.create_refresh_token
def create_refresh_token(user_id, access_token):
    token = str(uuid4())
    refresh_tokens.append({
        "token": token,
        "mapped_token": access_token,
        "user_id": user_id,
        "expires_at": datetime.utcnow() + timedelta(days=7),
        "revoked": False
    })

    return token

@app.route("/token/refresh_access_token", methods=["POST"])
@tok_schema.refresh_access_token
def refresh_access_token():
    pass

@app.route("/")
@tok_schema.tokens_required
def test_route():
    return "test"
```