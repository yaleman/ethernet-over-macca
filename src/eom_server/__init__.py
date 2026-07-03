"""Server implementations for EoMacca protocol.

Submodules are imported lazily via :pep:`562` ``__getattr__`` so that
``python -m eom_server.tcp_server`` does not trigger a runpy
``RuntimeWarning`` about the module already being in ``sys.modules``.
``from eom_server import TCPServer`` still works as expected.
"""

from typing import Any

__all__ = ["TCPServer", "HTTPServer", "RequestHandler"]


def __getattr__(name: str) -> Any:
    """Lazy-import server classes on first attribute access."""
    if name == "TCPServer":
        from .tcp_server import TCPServer  # noqa: PLC0415

        return TCPServer
    if name == "HTTPServer":
        from .http_server import HTTPServer  # noqa: PLC0415

        return HTTPServer
    if name == "RequestHandler":
        from .handlers import RequestHandler  # noqa: PLC0415

        return RequestHandler
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """Support ``dir(eom_server)`` and tab-completion."""
    return sorted(__all__ + list(globals().keys()))
