"""Main protocol stack implementation for EoMacca."""

from ethernet_over_macca.encapsulation import (
    INNER_SRC_IP,
    INNER_DST_IP,
    INNER_SRC_PORT,
    INNER_DST_PORT,
)

from ethernet_over_macca.stats import PayloadStats

from .encapsulation import (
    EomWrangler,
    OUTER_DST_IP,
    OUTER_DST_MAC,
    OUTER_DST_PORT,
    OUTER_SRC_IP,
    OUTER_SRC_MAC,
    OUTER_SRC_PORT,
)

from scapy.config import conf
from scapy.layers.l2 import Ether


conf.padding = 0
DEFAULT_STACK_ORDER = "ETHDtie"  # Default stack order for encapsulation/decapsulation, as seen by the receiver


class EoMaccaStack:
    """The complete EoMacca protocol stack implementation.

    This class handles the full 8-layer encapsulation process:
    Ethernet -> IP -> TCP -> HTTP -> DNS -> TCP -> IP -> Ethernet
    """

    def __init__(
        self,
        inner_src_ip: str = INNER_SRC_IP,
        inner_dst_ip: str = INNER_DST_IP,
        inner_src_port: int = INNER_SRC_PORT,
        inner_dst_port: int = INNER_DST_PORT,
        outer_src_ip: str = OUTER_SRC_IP,
        outer_dst_ip: str = OUTER_DST_IP,
        outer_src_port: int = OUTER_SRC_PORT,
        outer_dst_port: int = OUTER_DST_PORT,
        outer_src_mac: str = OUTER_SRC_MAC,
        outer_dst_mac: str = OUTER_DST_MAC,
        stack_order: str = DEFAULT_STACK_ORDER,
    ) -> None:
        """Initialize the EoMacca protocol stack.

        Args:
            stack_order: String representing the order of layers to encapsulate (as seen by the receiver).
                Default is "ETHDtie" (Ethernet, TCP, HTTP, DNS, inner TCP, inner IP, inner Ethernet).
            you can figure the rest out
        """
        self.outer_src_ip = outer_src_ip
        self.outer_dst_ip = outer_dst_ip
        self.outer_src_port = outer_src_port
        self.outer_dst_port = outer_dst_port
        self.outer_src_mac = outer_src_mac
        self.outer_dst_mac = outer_dst_mac
        self.wrangler = EomWrangler(
            inner_src_ip=inner_src_ip,
            inner_dst_ip=inner_dst_ip,
            inner_src_port=inner_src_port,
            inner_dst_port=inner_dst_port,
            outer_src_ip=outer_src_ip,
            outer_dst_ip=outer_dst_ip,
            outer_src_port=outer_src_port,
            outer_dst_port=outer_dst_port,
        )
        self.stack_order = stack_order  # Default stack order for encapsulation/decapsulation, as seen by the receiver

    def encapsulate(self, payload: bytes) -> bytes:
        """Encapsulate payload through all 8 layers of the protocol stack.

        Args:
            payload: The actual data to transmit

        Returns:
            Fully encapsulated packet bytes ready for transmission
        """

        for layer in reversed(self.stack_order):
            if layer == "e":
                # Layer 1: Create inner Ethernet frame with payload
                payload = self.wrangler.encapsulate_payload_frame(payload)
            elif layer == "i":
                # Layer 2: Encapsulate inner Ethernet in inner IP
                payload = self.wrangler.encapsulate_ethernet_in_tcp_ip(payload)
            elif layer == "t":
                # Layer 3: Encapsulate inner IP in inner TCP
                payload = self.wrangler.encapsulate_ip_in_tcp(payload)
            elif layer == "D":
                # Layer 4: Encapsulate inner TCP in DNS
                payload = self.wrangler.encapsulate_tcp_in_dns(payload)
            elif layer == "H":
                # Layer 5: Encapsulate DNS in HTTP
                payload = self.wrangler.encapsulate_dns_in_http(payload)
            elif layer == "T":
                # Layer 6: Encapsulate HTTP in outer TCP
                payload = self.wrangler.encapsulate_http_in_ip(payload)

            elif layer == "E":
                # Layer 7: Outer IP (already included in scapy packet above)
                # Layer 8: Outer Ethernet
                payload = self.wrangler.encapsulate_bytes_in_ethernet(payload)
            else:
                raise ValueError(f"Unsupported layer '{layer}' in stack_order")
        return bytes(payload)

    def decapsulate(self, payload: bytes | Ether) -> bytes:
        """Decapsulate a full EoMacca packet to extract the original payload.

        Args:
            payload: Complete EoMacca packet bytes
        Returns:
            Original payload bytes

        Raises:
            ValueError: If packet is malformed or cannot be decapsulated
        """

        for layer in self.stack_order:
            if layer == "E":
                # v1 Layer 8+7: Parse outer Ethernet and IP data
                payload = self.wrangler.parse_outer_ethernet(payload)
            elif layer == "T":
                # v1 Layer 6: Extract outer TCP and get payload bytes
                payload = self.wrangler.decapsulate_ether_to_tcp_bytes(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "H":
                # v1 Layer 5: Extract HTTP bytes to get DNS
                payload = self.wrangler.decapsulate_http_to_payload(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "D":
                # v1 Layer 4: Extract DNS bytes to get inner TCP
                payload = self.wrangler.decapsulate_dns_to_tcp(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "t":
                # v1 Layer 3: Extract inner TCP payload to get inner IP
                payload = self.wrangler.decapsulate_tcp_to_ip(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "i":
                # Layer 2: Extract inner IP payload to get inner Ethernet
                payload = self.wrangler.decapsulate_ip_to_ethernet(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "e":
                # Layer 1: Parse inner Ethernet to get payload
                payload = self.wrangler.decapsulate_bytes_to_payload(payload)  # ty:ignore[invalid-argument-type]
            else:
                raise ValueError(f"Unsupported layer '{layer}' in stack_order")

        return payload  # ty:ignore[invalid-return-type]

    def get_overhead_stats(self, payload: bytes) -> PayloadStats:
        """Calculate overhead statistics for a given payload.

        Args:
            payload: The payload to calculate stats for

        Returns:
            PayloadStats containing overhead statistics
        """
        encapsulated = self.encapsulate(payload)

        payload_size = len(payload)
        total_size = len(encapsulated)
        header_size = total_size - payload_size
        overhead_ratio = (header_size / payload_size) if payload_size > 0 else 0
        efficiency = (payload_size / total_size * 100) if total_size > 0 else 0

        return PayloadStats(
            payload_size=payload_size,
            total_size=total_size,
            header_size=header_size,
            overhead_ratio=overhead_ratio,
            efficiency_percent=efficiency,
        )
