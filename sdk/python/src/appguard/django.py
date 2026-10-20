"""Wrap Django's ASGI application before request parsing."""

from .asgi import AppGuardMiddleware


def protect_django(app, **kwargs):
    return AppGuardMiddleware(app, **kwargs)
