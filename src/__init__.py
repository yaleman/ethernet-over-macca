"""Ethernet over Macca (EoMacca) Protocol Implementation.

This module implements the 8-layer protocol stack defined in RFC 9999.
"""

from .protocol_stack import EoMaccaStack
from .encapsulation import (
    encapsulate_ethernet_in_ip,
    encapsulate_ip_in_tcp,
    encapsulate_tcp_in_dns,
    encapsulate_dns_in_http,
    decapsulate_http_to_dns,
    decapsulate_dns_to_tcp,
    decapsulate_tcp_to_ip,
    decapsulate_ip_to_ethernet,
)

__version__ = "0.1.0"
__all__ = [
    "EoMaccaStack",
    "encapsulate_ethernet_in_ip",
    "encapsulate_ip_in_tcp",
    "encapsulate_tcp_in_dns",
    "encapsulate_dns_in_http",
    "decapsulate_http_to_dns",
    "decapsulate_dns_to_tcp",
    "decapsulate_tcp_to_ip",
    "decapsulate_ip_to_ethernet",
]
