"""Layer-by-layer encapsulation functions for EoMacca protocol."""

from dataclasses import dataclass

from scapy.layers.l2 import Ether

import base64
from typing import Final

from dnslib import DNSRecord, DNSQuestion, DNSHeader, RR, QTYPE, TXT  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


INNER_SRC_IP: Final[str] = "10.255.255.1"
INNER_DST_IP: Final[str] = "10.255.255.2"
INNER_SRC_PORT: Final[int] = 31337
INNER_DST_PORT: Final[int] = 31338
# Outer layer defaults
OUTER_SRC_IP: Final[str] = "192.168.1.100"
OUTER_SRC_PORT: Final[int] = 54321
OUTER_SRC_MAC: Final[str] = "00:11:22:33:44:55"

OUTER_DST_IP: Final[str] = "192.168.1.200"
OUTER_DST_PORT: Final[int] = 9999  # EoMacca default port
OUTER_DST_MAC: Final[str] = "aa:bb:cc:dd:ee:ff"

DNS_DOMAIN: Final[str] = "data.eomacca.example.com"
HTTP_HOST: Final[str] = "eomacca.example.com"
HTTP_PATH: Final[str] = "/eomacca/v1/tunnel"
HTTP_CONTENT_TYPE: Final[str] = "application/octet-stream"
HTTP_USER_AGENT: Final[str] = "EoMacca/1.0 (Unnecessarily Complex Protocol)"

MIN_ETH_HEADER: Final[int] = 14
MIN_IP_HEADER: Final[int] = 20
MIN_TCP_HEADER: Final[int] = 20


@dataclass
class EomWrangler:
    """Encapsulation functions for EoMacca protocol."""

    inner_src_ip: str = INNER_SRC_IP
    inner_dst_ip: str = INNER_DST_IP
    inner_src_port: int = INNER_SRC_PORT
    inner_dst_port: int = INNER_DST_PORT
    outer_src_ip: str = OUTER_SRC_IP
    outer_dst_ip: str = OUTER_DST_IP
    outer_src_port: int = OUTER_SRC_PORT
    outer_dst_port: int = OUTER_DST_PORT
    outer_src_mac: str = OUTER_SRC_MAC
    outer_dst_mac: str = OUTER_DST_MAC
    dns_domain: str = DNS_DOMAIN
    http_host: str = HTTP_HOST
    http_path: str = HTTP_PATH
    http_content_type: str = HTTP_CONTENT_TYPE
    user_agent: str = HTTP_USER_AGENT

    def encapsulate_ethernet_in_tcp_ip(self, eth_frame: bytes) -> bytes:
        """Encapsulate an Ethernet frame as the payload of a TCP/IP packet.

        Args:
            eth_frame: Raw Ethernet frame bytes

        Returns:
            Raw IP packet bytes containing the Ethernet frame
        """
        ip_packet = IP(
            src=self.inner_src_ip,
            dst=self.inner_dst_ip,
            proto=6,
        ) / Raw(load=eth_frame)

        return bytes(ip_packet)

    def encapsulate_raw_bytes(self, payload: bytes) -> bytes:
        return bytes(
            Ether(src=self.outer_src_mac, dst=self.outer_dst_mac) / Raw(load=payload)
        )

    def encapsulate_packet_in_ethernet(self, payload: IP) -> bytes:
        """takes a scapy packet and encapsulates it in an ethernet frame"""
        return Ether(src=self.outer_src_mac, dst=self.outer_dst_mac) / payload

    def encapsulate_bytes_in_tcp_ip(self, http_request: bytes) -> bytes:
        """Returns a raw-encoded packet"""
        return (
            IP(src=self.outer_src_ip, dst=self.outer_dst_ip)
            / TCP(
                sport=self.outer_src_port,
                dport=self.outer_dst_port,
                flags="PA",
                seq=2000,
                ack=2000,
            )
            / Raw(load=http_request)
        )

    def encapsulate_ip_in_tcp(self, ip_packet: bytes) -> bytes:
        """Encapsulate an IP packet as the payload of a TCP segment.

        Args:
            ip_packet: Raw IP packet bytes

        Returns:
            Raw TCP segment bytes containing the IP packet
        """
        tcp_segment = (
            IP(src=self.inner_src_ip, dst=self.inner_dst_ip)
            / TCP(
                sport=self.inner_src_port,
                dport=self.inner_dst_port,
                flags="PA",
                seq=1000,
                ack=1000,
            )
            / Raw(load=ip_packet)
        )

        return bytes(tcp_segment)

    def encapsulate_tcp_in_dns(self, tcp_segment: bytes) -> bytes:
        """Encapsulate a TCP segment in a DNS TXT record.

        Args:
            tcp_segment: Raw TCP segment bytes

        Returns:
            Raw DNS message bytes containing the base64-encoded TCP segment
        """
        encoded_data = base64.b64encode(tcp_segment).decode("ascii")

        chunk_size = 250
        chunks = [
            encoded_data[i : i + chunk_size]
            for i in range(0, len(encoded_data), chunk_size)
        ]

        dns_msg = DNSRecord(
            DNSHeader(
                qr=1,
                aa=1,
                rd=1,
                ra=1,
            ),
            q=DNSQuestion(DNS_DOMAIN, QTYPE.TXT),
        )

        dns_msg.add_answer(
            RR(
                rname=DNS_DOMAIN,
                rtype=QTYPE.TXT,
                rclass=1,
                ttl=0,
                rdata=TXT(chunks),
            )
        )

        return dns_msg.pack()  # type: ignore[no-any-return]

    def encapsulate_http(self, payload_bytes: bytes) -> bytes:
        """Encapsulate a DNS message in an HTTP POST request.

        Args:
            payload_bytes: Raw DNS message bytes

        Returns:
            Raw HTTP request bytes
        """
        http_request = (
            f"POST {self.http_path} HTTP/1.1\r\n"
            f"Host: {self.http_host}\r\n"
            f"Content-Type: {self.http_content_type}\r\n"
            f"Content-Length: {len(payload_bytes)}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Cookie: overhead=yes\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode("ascii")
        return http_request + payload_bytes

    def decapsulate_http_to_payload(self, http_data: bytes) -> bytes:
        """Extract payload from HTTP request/response.

        Args:
            http_data: Raw HTTP request or response bytes

        Returns:
            Raw payload bytes

        Raises:
            ValueError: If HTTP data is malformed
        """
        if len(http_data) < 16:
            raise ValueError("HTTP data too short to contain valid headers")

        header_end = http_data.find(b"\r\n\r\n")
        if header_end == -1:
            raise ValueError("Invalid HTTP message: no header terminator found")

        payload = http_data[header_end + 4 :]

        if len(payload) == 0:
            raise ValueError("HTTP message has no body")

        return payload

    def decapsulate_dns_to_tcp(self, dns_message: bytes) -> bytes:
        """Extract TCP segment from DNS TXT record.

        Args:
            dns_message: Raw DNS message bytes

        Returns:
            Raw TCP segment bytes

        Raises:
            ValueError: If DNS message is malformed or has no TXT record
        """
        if len(dns_message) < 12:
            raise ValueError("DNS message too short to contain valid header")

        try:
            dns_record = DNSRecord.parse(dns_message)
        except Exception as e:
            raise ValueError(f"Failed to parse DNS message: {e}") from e

        if not dns_record.rr:
            raise ValueError("DNS message has no answer records")

        txt_record = dns_record.rr[0]
        if txt_record.rtype != QTYPE.TXT:
            raise ValueError(f"Expected TXT record, got {QTYPE[txt_record.rtype]}")

        txt_rdata = txt_record.rdata
        if hasattr(txt_rdata, "data"):
            txt_data = "".join(
                chunk.decode("ascii") if isinstance(chunk, bytes) else chunk
                for chunk in txt_rdata.data
            )
        else:
            txt_data = str(txt_rdata)

        if not txt_data:
            raise ValueError("DNS TXT record is empty")

        try:
            tcp_segment = base64.b64decode(txt_data)
        except Exception as e:
            raise ValueError(f"Failed to decode base64 from DNS TXT: {e}") from e

        return tcp_segment

    def decapsulate_tcp_to_ip(self, outer_bytes: bytes) -> bytes:
        """Extract IP packet from TCP segment payload.

        Args:
            outer_bytes: Raw TCP segment bytes (including IP header)

        Returns:
            Raw inner IP packet bytes

        Raises:
            ValueError: If TCP data is malformed
        """
        min_total = MIN_IP_HEADER + MIN_TCP_HEADER
        if len(outer_bytes) < min_total:
            raise ValueError(
                f"TCP segment too short: {len(outer_bytes)} bytes, minimum is {min_total}"
            )

        try:
            packet = IP(outer_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse IP packet: {e}") from e

        if not packet.haslayer(TCP):
            raise ValueError("Data does not contain a TCP layer")

        tcp_layer = packet[TCP]

        if not tcp_layer.payload:
            raise ValueError("TCP segment has no payload")

        payload = bytes(tcp_layer.payload)

        if len(payload) < MIN_IP_HEADER:
            raise ValueError(
                f"TCP payload too short for IP packet: {len(payload)} bytes"
            )

        return payload

    def decapsulate_ip_to_ethernet(self, outer_bytes: bytes) -> bytes:
        """Extract Ethernet frame from IP packet payload.

        Args:
            outer_bytes: Raw IP packet bytes

        Returns:
            Raw Ethernet frame bytes

        Raises:
            ValueError: If IP data is malformed
        """
        if len(outer_bytes) < MIN_IP_HEADER:
            raise ValueError(
                f"IP packet too short: {len(outer_bytes)} bytes, minimum is {MIN_IP_HEADER}"
            )

        try:
            packet = IP(outer_bytes)
        except Exception as e:
            raise ValueError(f"Failed to parse inner IP packet: {e}") from e

        if not packet.payload:
            raise ValueError("IP packet has no payload")

        payload = bytes(packet.payload)

        if len(payload) < MIN_ETH_HEADER:
            raise ValueError(
                f"IP payload too short for Ethernet frame: {len(payload)} bytes"
            )

        return payload

    def decapsulate_bytes_to_payload(self, outer_bytes: bytes) -> bytes:
        """Take raw bytes of an Ethernet frame and extract the payload, if any."""
        inner_eth = Ether(outer_bytes)
        if not inner_eth.payload:
            # Empty payload is valid
            return b""

        return bytes(inner_eth.payload)

    @classmethod
    def decapsulate_eoip(cls, packet_bytes: bytes | Ether) -> Ether:
        """Parse raw bytes into an outer Ethernet packet."""
        if isinstance(packet_bytes, bytes):
            outer_packet = Ether(packet_bytes)
        else:
            outer_packet = packet_bytes

        if not outer_packet.haslayer(IP):
            raise ValueError("No outer IP layer found")
        return outer_packet

    @classmethod
    def decapsulate_ether_to_tcp_bytes(cls, packet_bytes: Ether) -> bytes:
        """Extract the payload from the outer TCP layer of an Ethernet packet."""
        if not packet_bytes.haslayer(TCP):
            raise ValueError("No outer TCP layer found")

        tcp_layer = packet_bytes[TCP]
        if not tcp_layer.payload:
            raise ValueError("Outer TCP has no payload")
        return bytes(tcp_layer.payload)
