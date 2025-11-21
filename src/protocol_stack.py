"""Main protocol stack implementation for EoMacca."""

from typing import Final

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

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
        inner_ip = encapsulate_ethernet_in_ip(inner_eth_bytes)

        # Layer 3: Encapsulate inner IP in inner TCP
        inner_tcp = encapsulate_ip_in_tcp(inner_ip)

        # Layer 4: Encapsulate inner TCP in DNS
        dns_msg = encapsulate_tcp_in_dns(inner_tcp)

        # Layer 5: Encapsulate DNS in HTTP
        http_data = encapsulate_dns_in_http(dns_msg)

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

    def decapsulate(self, packet_bytes: bytes) -> bytes:
        """Decapsulate a full EoMacca packet to extract the original payload.

        Args:
            packet_bytes: Complete EoMacca packet bytes

        Returns:
            Original payload bytes

        Raises:
            ValueError: If packet is malformed or cannot be decapsulated
        """
        # Layer 8: Parse outer Ethernet
        outer_packet = Ether(packet_bytes)

        if not outer_packet.haslayer(IP):
            raise ValueError("No outer IP layer found")

        # Layer 7: Outer IP already parsed
        # Layer 6: Extract outer TCP and get HTTP data
        if not outer_packet.haslayer(TCP):
            raise ValueError("No outer TCP layer found")

        tcp_layer = outer_packet[TCP]
        if not tcp_layer.payload:
            raise ValueError("Outer TCP has no payload")

        # Layer 5: Extract HTTP payload to get DNS
        http_data = bytes(tcp_layer.payload)
        dns_msg = decapsulate_http_to_dns(http_data)

        # Layer 4: Extract DNS payload to get inner TCP
        inner_tcp = decapsulate_dns_to_tcp(dns_msg)

        # Layer 3: Extract inner TCP payload to get inner IP
        inner_ip = decapsulate_tcp_to_ip(inner_tcp)

        # Layer 2: Extract inner IP payload to get inner Ethernet
        inner_eth_bytes = decapsulate_ip_to_ethernet(inner_ip)

        # Layer 1: Parse inner Ethernet to get payload
        inner_eth = Ether(inner_eth_bytes)
        if not inner_eth.payload:
            # Empty payload is valid
            return b""

        payload = bytes(inner_eth.payload)
        return payload

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
