"""Shared CLI argument parsing for EoMacca servers and demos.

Consolidates the ``--layers ORDER`` flag and the server ``mode`` positional
argument so the TCP server, HTTP server, and demo entry points all use the
same parser logic. No private (underscore-prefixed) functions here.
"""

from __future__ import annotations

import argparse
from typing import Literal, Sequence

LAYER_ORDER_EPILOG = (
    "ORDER is a v2 layer-order string, decap order (outer -> inner), "
    "e.g. 'THDtIE' (outer TCP, HTTP, DNS, inner TCP, inner IP, inner Eth). "
    "Defaults to the v1-compatible stack."
)

SERVER_MODES: tuple[Literal["echo", "chat", "file", "ping"], ...] = (
    "echo",
    "chat",
    "file",
    "ping",
)


def add_layers_argument(parser: argparse.ArgumentParser) -> None:
    """Add the ``--layers ORDER`` argument to ``parser``."""
    parser.add_argument(
        "--layers",
        metavar="ORDER",
        default=None,
        help="v2 layer-order string (default: v1-compatible stack)",
    )


def build_server_arg_parser(prog: str, description: str) -> argparse.ArgumentParser:
    """Build the argparse parser used by both the TCP and HTTP servers.

    Exposes a positional ``mode`` (defaulting to ``echo``) and the
    ``--layers ORDER`` flag.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=LAYER_ORDER_EPILOG,
    )
    parser.add_argument(
        "mode",
        nargs="?",
        default="echo",
        choices=list(SERVER_MODES),
        help="server mode (default: echo)",
    )
    add_layers_argument(parser)
    return parser


def parse_server_args(
    argv: Sequence[str] | None = None,
) -> tuple[Literal["echo", "chat", "file", "ping"], str | None]:
    """Parse argv for an EoMacca server (TCP or HTTP).

    Returns ``(mode, layer_order)``. Argparse handles ``--help`` / bad input.
    """
    parser = build_server_arg_parser(
        prog="eom_server",
        description="EoMacca server.",
    )
    parsed = parser.parse_args(argv)
    mode: Literal["echo", "chat", "file", "ping"] = parsed.mode
    return mode, parsed.layers


def parse_demo_layer_order(prog: str, argv: Sequence[str] | None = None) -> str | None:
    """Parse ``--layers ORDER`` from argv for a demo program.

    The layer-order string is a v2 layer sequence like ``"THDtIE"``
    (see :func:`ethernet_over_macca.encapsulation.parse_layer_order`).
    Other positional args are ignored so demos can stay simple.

    Argparse handles ``--help`` / bad input with a usage message.
    """
    parser = argparse.ArgumentParser(
        prog=prog,
        description="EoMacca protocol demo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=LAYER_ORDER_EPILOG,
    )
    add_layers_argument(parser)
    parsed, _ = parser.parse_known_args(list(argv) if argv is not None else None)
    return parsed.layers
