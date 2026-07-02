"""Main protocol stack implementation for EoMacca."""

from typing import Final

from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from .encapsulation import Encapsulator

conf.padding = 0

# Outer layer defaults
OUTER_SRC_IP: Final[str] = "192.168.1.100"
OUTER_DST_IP: Final[str] = "192.168.1.200"
OUTER_SRC_PORT: Final[int] = 54321
OUTER_DST_PORT: Final[int] = 9999  # EoMacca default port
OUTER_SRC_MAC: Final[str] = "00:11:22:33:44:55"
OUTER_DST_MAC: Final[str] = "aa:bb:cc:dd:ee:ff"


class EoMaccaStack:
    """The complete EoMacca protocol stack implementation.

    This class handles the full 8-layer encapsulation process:
    Ethernet -> IP -> TCP -> HTTP -> DNS -> TCP -> IP -> Ethernet
    """

    def __init__(
        self,
        outer_src_ip: str = OUTER_SRC_IP,
        outer_dst_ip: str = OUTER_DST_IP,
        outer_src_port: int = OUTER_SRC_PORT,
        outer_dst_port: int = OUTER_DST_PORT,
        outer_src_mac: str = OUTER_SRC_MAC,
        outer_dst_mac: str = OUTER_DST_MAC,
    ) -> None:
        """Initialize the EoMacca protocol stack.

        Args:
            outer_src_ip: Source IP for outer IP layer
            outer_dst_ip: Destination IP for outer IP layer
            outer_src_port: Source port for outer TCP layer
            outer_dst_port: Destination port for outer TCP layer
            outer_src_mac: Source MAC for outer Ethernet layer
            outer_dst_mac: Destination MAC for outer Ethernet layer
        """
        self.outer_src_ip = outer_src_ip
        self.outer_dst_ip = outer_dst_ip
        self.outer_src_port = outer_src_port
        self.outer_dst_port = outer_dst_port
        self.outer_src_mac = outer_src_mac
        self.outer_dst_mac = outer_dst_mac
        self.encapsulator = Encapsulator()

    def encapsulate(self, payload: bytes) -> bytes:
        """Encapsulate payload through all 8 layers of the protocol stack.

        Args:
            payload: The actual data to transmit

        Returns:
            Fully encapsulated packet bytes ready for transmission
        """
        # Layer 1: Create inner Ethernet frame with payload
        inner_eth = Ether(src="de:ad:be:ef:ca:fe", dst="fe:ed:fa:ce:de:ad") / Raw(
            load=payload
        )
        inner_eth_bytes = bytes(inner_eth)

        # Layer 2: Encapsulate inner Ethernet in inner IP
        inner_ip = self.encapsulator.encapsulate_ethernet_in_ip(inner_eth_bytes)

        # Layer 3: Encapsulate inner IP in inner TCP
        inner_tcp = self.encapsulator.encapsulate_ip_in_tcp(inner_ip)

        # Layer 4: Encapsulate inner TCP in DNS
        dns_msg = self.encapsulator.encapsulate_tcp_in_dns(inner_tcp)

        # Layer 5: Encapsulate DNS in HTTP
        http_data = self.encapsulator.encapsulate_dns_in_http(dns_msg)

        # Layer 6: Encapsulate HTTP in outer TCP
        outer_tcp = (
            IP(src=self.outer_src_ip, dst=self.outer_dst_ip)
            / TCP(
                sport=self.outer_src_port,
                dport=self.outer_dst_port,
                flags="PA",
                seq=2000,
                ack=2000,
            )
            / Raw(load=http_data)
        )

        # Layer 7: Outer IP (already included in scapy packet above)
        # Layer 8: Outer Ethernet
        outer_packet = Ether(src=self.outer_src_mac, dst=self.outer_dst_mac) / outer_tcp

        return bytes(outer_packet)

    def decapsulate(self, payload: bytes | Ether, stack_order="ETHDtie") -> bytes:
        """Decapsulate a full EoMacca packet to extract the original payload.

        Args:
            payload: Complete EoMacca packet bytes
            stack_order: String representing the order of layers to decapsulate.
                Default is "ETHDtie" (Ethernet, TCP, HTTP, DNS, inner TCP, inner IP, inner Ethernet).
        Returns:
            Original payload bytes

        Raises:
            ValueError: If packet is malformed or cannot be decapsulated
        """

        for layer in stack_order:
            if layer == "E":
                # v1 Layer 8+7: Parse outer Ethernet and IP data
                payload = self.encapsulator.parse_outer_ethernet(payload)
            elif layer == "T":
                # v1 Layer 6: Extract outer TCP and get payload bytes
                payload = self.encapsulator.decapsulate_ether_to_tcp_bytes(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "H":
                # v1 Layer 5: Extract HTTP bytes to get DNS
                payload = self.encapsulator.decapsulate_http_to_payload(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "D":
                # v1 Layer 4: Extract DNS bytes to get inner TCP
                payload = self.encapsulator.decapsulate_dns_to_tcp(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "t":
                # v1 Layer 3: Extract inner TCP payload to get inner IP
                payload = self.encapsulator.decapsulate_tcp_to_ip(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "i":
                # Layer 2: Extract inner IP payload to get inner Ethernet
                payload = self.encapsulator.decapsulate_ip_to_ethernet(payload)  # ty:ignore[invalid-argument-type]
            elif layer == "e":
                # Layer 1: Parse inner Ethernet to get payload
                payload = self.encapsulator.decapsulate_bytes_to_payload(payload)  # ty:ignore[invalid-argument-type]
            else:
                raise ValueError(f"Unsupported layer '{layer}' in stack_order")

        return payload  # ty:ignore[invalid-return-type]

    def get_overhead_stats(self, payload: bytes) -> dict[str, int | float]:
        """Calculate overhead statistics for a given payload.

        Args:
            payload: The payload to calculate stats for

        Returns:
            Dictionary containing overhead statistics
        """
        encapsulated = self.encapsulate(payload)

        payload_size = len(payload)
        total_size = len(encapsulated)
        header_size = total_size - payload_size
        overhead_ratio = (header_size / payload_size) if payload_size > 0 else 0
        efficiency = (payload_size / total_size * 100) if total_size > 0 else 0

        return {
            "payload_size": payload_size,
            "total_size": total_size,
            "header_size": header_size,
            "overhead_ratio": overhead_ratio,
            "efficiency_percent": efficiency,
        }
