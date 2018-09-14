from werkzeug.http import parse_cookie

def get_cookie(response, name, type=str):
    cookies = response.headers.getlist('Set-Cookie')
    for cookie in cookies:
        c = parse_cookie(cookie)
        if name in c:
            return c.get(name, type=type)
    
    return ""