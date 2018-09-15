from token_schema import (set_token_cookies, get_access_token_from_cookie,
                          get_refresh_token_from_cookie, encode_jwt)

from helpers import get_cookie


def test_cookies(client, app, tok_schema):
    response = client.get("/set_cookies")
    access_token = get_cookie(response, app.config["ACCESS_COOKIE_NAME"])
    refresh_token = get_cookie(response, app.config["REFRESH_COOKIE_NAME"])
    assert access_token and refresh_token

    client.set_cookie(
        "localhost",
        app.config["ACCESS_COOKIE_NAME"],
        access_token,
        httponly=True)
    client.set_cookie(
        "localhost",
        app.config["REFRESH_COOKIE_NAME"],
        refresh_token,
        httponly=True)
    response = client.post("/token/refresh_access_token")
    response = client.get("/get_cookies")
    resp_access_token, resp_refresh_token = response.get_json()

    assert access_token == resp_access_token
    assert refresh_token == resp_refresh_token
