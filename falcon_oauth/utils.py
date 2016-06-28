import base64

import falcon
from oauthlib.common import to_unicode, bytes_type


def to_bytes(text, encoding='utf-8'):
    """Make sure text is bytes type."""
    if not text:
        return text
    if not isinstance(text, bytes_type):
        text = text.encode(encoding)
    return text


def decode_base64(text, encoding='utf-8'):
    """Decode base64 string."""
    text = to_bytes(text, encoding)
    return to_unicode(base64.b64decode(text), encoding)


def extract_params(req):
    if hasattr(req.stream, 'seek'):
        # When consuming body for urlencoded form parsing, Falcon does not
        # reset it.
        # See https://github.com/falconry/falcon/pull/649.
        req.stream.seek(0)
    body = req.stream.read()
    if not body:
        # Body is non seekable and someone already consumed it?
        # OAuthlib accepts also dict, so let's fallback to this.
        body = req.params
    return req.uri, req.method, body, req.headers


def patch_response(resp, headers, body, status):
    if body:
        resp.body = body
    resp.set_headers(headers)
    if isinstance(status, int):
        status = getattr(falcon, 'HTTP_{}'.format(status))
    resp.status = status
    return resp


def maybe_args(decorator):
    """Decorate a method decorator to make its args optional."""
    def wrapped_decorator(klass, *args):
        if len(args) == 1 and callable(args[0]):
            return decorator(klass, *args)
        else:
            def real_decorator(method):
                return decorator(klass, method, *args)
            return real_decorator
    return wrapped_decorator
