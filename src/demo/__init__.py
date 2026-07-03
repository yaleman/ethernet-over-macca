"""Demo applications for EoMacca protocol."""

import argparse
from typing import Sequence


def parse_demo_args(program: str) -> str | None:
    """Parse ``--layers ORDER`` from argv for a demo program.

    The layer-order string is a v2 layer sequence like ``"THDtIE"``
    (see :func:`ethernet_over_macca.encapsulation.parse_layer_order`).
    Other positional args are ignored so demos can stay simple.

    Argparse handles ``--help`` / bad input with a usage message.
    """
    parser = argparse.ArgumentParser(
        prog=program,
        description="EoMacca protocol demo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "ORDER is a v2 layer-order string, decap order (outer -> inner), "
            "e.g. 'THDtIE'. Defaults to the v1-compatible stack."
        ),
    )
    parser.add_argument(
        "--layers",
        metavar="ORDER",
        default=None,
        help="v2 layer-order string (default: v1-compatible stack)",
    )
    parsed, _ = parser.parse_known_args()
    return parsed.layers


def parse_demo_args_from(program: str, argv: Sequence[str]) -> str | None:
    """Variant of :func:`parse_demo_args` taking argv explicitly (for tests)."""
    parser = argparse.ArgumentParser(
        prog=program,
        description="EoMacca protocol demo.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "ORDER is a v2 layer-order string, decap order (outer -> inner), "
            "e.g. 'THDtIE'. Defaults to the v1-compatible stack."
        ),
    )
    parser.add_argument(
        "--layers",
        metavar="ORDER",
        default=None,
        help="v2 layer-order string (default: v1-compatible stack)",
    )
    parsed, _ = parser.parse_known_args(list(argv))
    return parsed.layers
