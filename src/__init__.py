"""Ethernet over Macca (EoMacca) Protocol Implementation.

This module implements the 8-layer protocol stack defined in RFC 9999.
"""

from ethernet_over_macca.protocol_stack import EoMaccaStack

__version__ = "0.1.0"
__all__ = [
    "EoMaccaStack",
    "Encapsulator",
]
