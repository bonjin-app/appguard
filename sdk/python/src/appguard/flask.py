def protect_flask(app, **kwargs):
    """Deploy the returned ASGI app; verify before WSGI can discard evidence."""
    from asgiref.wsgi import WsgiToAsgi
    from .asgi import AppGuardMiddleware, _header_pairs, _respond
    from .types import VerificationError

    def verified_wsgi(environ, start_response):
        # The outer verifier has bounded and authenticated the full body, and
        # WsgiToAsgi has buffered it in an EOF-terminated file. Werkzeug may
        # otherwise hide a body with no Content-Length (including chunked input).
        # Preserve the original headers instead of inventing framing metadata.
        environ["wsgi.input_terminated"] = True
        return app(environ, start_response)

    verifier = AppGuardMiddleware(WsgiToAsgi(verified_wsgi), **kwargs)

    async def protected(scope, receive, send):
        if scope["type"] == "http":
            try:
                mapped = {}
                for name, _ in _header_pairs(scope):
                    name = name.lower()
                    wsgi_name = (name.upper() if name in {"content-type", "content-length"}
                                 else "HTTP_" + name.upper()).replace("-", "_")
                    if wsgi_name in mapped and mapped[wsgi_name] != name:
                        raise VerificationError("INVALID_REQUEST")
                    mapped[wsgi_name] = name
            except VerificationError:
                # WSGI merges dash/underscore aliases. Reject before auth or
                # nonce claim, while the original duplicate evidence exists.
                await _respond(send, 400, "INVALID_REQUEST")
                return
        await verifier(scope, receive, send)

    return protected
