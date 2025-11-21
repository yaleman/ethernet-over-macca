"""Layer-by-layer encapsulation functions for EoMacca protocol."""

import base64
from typing import Final

from dnslib import DNSRecord, DNSQuestion, DNSHeader, RR, QTYPE, TXT  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

# Constants
INNER_SRC_IP: Final[str] = "10.255.255.1"
INNER_DST_IP: Final[str] = "10.255.255.2"
INNER_SRC_PORT: Final[int] = 31337
INNER_DST_PORT: Final[int] = 31338
DNS_DOMAIN: Final[str] = "data.eomacca.example.com"
HTTP_HOST: Final[str] = "eomacca.example.com"
HTTP_PATH: Final[str] = "/eomacca/v1/tunnel"


def encapsulate_ethernet_in_ip(eth_frame: bytes) -> bytes:
    """Encapsulate an Ethernet frame as the payload of an IP packet.

    Args:
        eth_frame: Raw Ethernet frame bytes

    Returns:
        Raw IP packet bytes containing the Ethernet frame
    """
    ip_packet = IP(
        src=INNER_SRC_IP,
        dst=INNER_DST_IP,
        proto=6,  # TCP
    ) / Raw(load=eth_frame)

    return bytes(ip_packet)


def encapsulate_ip_in_tcp(ip_packet: bytes) -> bytes:
    """Encapsulate an IP packet as the payload of a TCP segment.

    Args:
        ip_packet: Raw IP packet bytes

    Returns:
        Raw TCP segment bytes containing the IP packet
    """
    tcp_segment = (
        IP(src=INNER_SRC_IP, dst=INNER_DST_IP)
        / TCP(
            sport=INNER_SRC_PORT,
            dport=INNER_DST_PORT,
            flags="PA",  # PSH, ACK
            seq=1000,
            ack=1000,
        )
        / Raw(load=ip_packet)
    )

    return bytes(tcp_segment)


def encapsulate_tcp_in_dns(tcp_segment: bytes) -> bytes:
    """Encapsulate a TCP segment in a DNS TXT record.

    Args:
        tcp_segment: Raw TCP segment bytes

    Returns:
        Raw DNS message bytes containing the base64-encoded TCP segment
    """
    # Base64 encode the TCP segment
    encoded_data = base64.b64encode(tcp_segment).decode("ascii")

    # DNS TXT records have a 255 character limit per string
    # Split the encoded data into chunks if necessary
    chunk_size = 250  # Leave some margin
    chunks = [
        encoded_data[i : i + chunk_size]
        for i in range(0, len(encoded_data), chunk_size)
    ]

    # Create DNS message
    dns_msg = DNSRecord(
        DNSHeader(
            qr=1,  # Response
            aa=1,  # Authoritative
            rd=1,  # Recursion desired
            ra=1,  # Recursion available
        ),
        q=DNSQuestion(DNS_DOMAIN, QTYPE.TXT),
    )

    # Add TXT record answer with chunks
    dns_msg.add_answer(
        RR(
            rname=DNS_DOMAIN,
            rtype=QTYPE.TXT,
            rclass=1,  # IN
            ttl=0,
            rdata=TXT(chunks),  # Pass list of chunks
        )
    )

    return dns_msg.pack()  # type: ignore[no-any-return]


def encapsulate_dns_in_http(dns_message: bytes) -> bytes:
    """Encapsulate a DNS message in an HTTP POST request.

    Args:
        dns_message: Raw DNS message bytes

    Returns:
        Raw HTTP request bytes
    """
    http_request = (
        f"POST {HTTP_PATH} HTTP/1.1\r\n"
        f"Host: {HTTP_HOST}\r\n"
        f"Content-Type: application/dns-message\r\n"
        f"Content-Length: {len(dns_message)}\r\n"
        f"User-Agent: EoMacca/1.0 (Unnecessarily Complex Protocol)\r\n"
        f"Cookie: overhead=yes\r\n"
        f"Connection: keep-alive\r\n"
        f"\r\n"
    ).encode("ascii")

    return http_request + dns_message


def decapsulate_http_to_dns(http_data: bytes) -> bytes:
    """Extract DNS message from HTTP request/response.

    Args:
        http_data: Raw HTTP request or response bytes

    Returns:
        Raw DNS message bytes

    Raises:
        ValueError: If HTTP data is malformed
    """
    # Find the end of headers (double CRLF)
    header_end = http_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise ValueError("Invalid HTTP message: no header terminator found")

    # DNS message is everything after the headers
    dns_message = http_data[header_end + 4 :]
    return dns_message


def decapsulate_dns_to_tcp(dns_message: bytes) -> bytes:
    """Extract TCP segment from DNS TXT record.

    Args:
        dns_message: Raw DNS message bytes

    Returns:
        Raw TCP segment bytes

    Raises:
        ValueError: If DNS message is malformed or has no TXT record
    """
    dns_record = DNSRecord.parse(dns_message)

    # Get the first answer (TXT record)
    if not dns_record.rr:
        raise ValueError("DNS message has no answer records")

    txt_record = dns_record.rr[0]
    if txt_record.rtype != QTYPE.TXT:
        raise ValueError(f"Expected TXT record, got {QTYPE[txt_record.rtype]}")

    # Extract and decode the base64 data
    # TXT data can be a list of strings (chunks), join them
    txt_rdata = txt_record.rdata
    if hasattr(txt_rdata, "data"):
        # Join all chunks together
        txt_data = "".join(
            chunk.decode("ascii") if isinstance(chunk, bytes) else chunk
            for chunk in txt_rdata.data
        )
    else:
        txt_data = str(txt_rdata)

    tcp_segment = base64.b64decode(txt_data)

    return tcp_segment


def decapsulate_tcp_to_ip(tcp_data: bytes) -> bytes:
    """Extract IP packet from TCP segment payload.

    Args:
        tcp_data: Raw TCP segment bytes (including IP header)

    Returns:
        Raw inner IP packet bytes

    Raises:
        ValueError: If TCP data is malformed
    """
    # Parse the outer IP+TCP packet
    packet = IP(tcp_data)

    if not packet.haslayer(TCP):
        raise ValueError("Data does not contain a TCP layer")

    tcp_layer = packet[TCP]

    # Extract the payload
    if not tcp_layer.payload:
        raise ValueError("TCP segment has no payload")

    payload = bytes(tcp_layer.payload)
    return payload


def decapsulate_ip_to_ethernet(ip_data: bytes) -> bytes:
    """Extract Ethernet frame from IP packet payload.

    Args:
        ip_data: Raw IP packet bytes

    Returns:
        Raw Ethernet frame bytes

    Raises:
        ValueError: If IP data is malformed
    """
    packet = IP(ip_data)

    if not packet.payload:
        raise ValueError("IP packet has no payload")

    payload = bytes(packet.payload)
    return payload
