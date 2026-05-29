"""GUI package for UDS Observer Toolkit."""


def main(*args, **kwargs):
    from .app import main as app_main
    return app_main(*args, **kwargs)

__all__ = ["main"]
