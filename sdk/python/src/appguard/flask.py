def protect_flask(app, **kwargs):
    """Deploy the returned ASGI app; verify before WSGI can discard evidence."""
    from asgiref.wsgi import WsgiToAsgi
    from .asgi import AppGuardMiddleware

    return AppGuardMiddleware(WsgiToAsgi(app), **kwargs)
