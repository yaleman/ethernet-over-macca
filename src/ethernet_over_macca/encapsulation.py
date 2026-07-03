"""Layer-by-layer encapsulation for the EoMacca v2 protocol.

v2 design principles (see REVIEW.md / RFC):

* Each layer has a uniform ``bytes -> bytes`` encap/decap contract.
* Each ``decapsulate_*`` function peels exactly one layer and is
  *non-greedy*: it consumes only the bytes that belong to its own layer,
  bounded by the layer's own length / offset fields, and returns the rest
  as the inner payload. This is what makes arbitrary inner orderings safe:
  a decap function never greedily parses past its own boundary.
* The outer Ethernet + outer IP envelope is a hard transport limit and is
  applied as a fixed outermost wrap outside the configurable layer stack.
* Layer orderings come from out-of-band config (``EoMaccaStack.layers``).
  There is no in-band negotiation: getting the order wrong yields a clean
  ``EomError`` (or garbage), by design.
"""

import base64
from dataclasses import dataclass
from enum import Enum
from typing import Final

import dnslib  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

# ---------------------------------------------------------------------------
# Default configuration constants
# ---------------------------------------------------------------------------

INNER_SRC_IP: Final[str] = "10.255.255.1"
INNER_DST_IP: Final[str] = "10.255.255.2"
INNER_SRC_PORT: Final[int] = 31337
INNER_DST_PORT: Final[int] = 31338

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
HTTP_USER_AGENT: Final[str] = "EoMacca/2.0 (Unnecessarily Complex Protocol)"

# Profile-internal sanity thresholds. The non-greedy decap relies on each
# layer's own length/offset fields, but we still reject obviously truncated
# buffers up-front so callers get typed errors instead of index errors.
MIN_ETH_HEADER: Final[int] = 14
MIN_IP_HEADER: Final[int] = 20
MIN_TCP_HEADER: Final[int] = 20


# ---------------------------------------------------------------------------
# Typed errors
# ---------------------------------------------------------------------------


class EomError(Exception):
    """Base class for all EoMacca encapsulation/decapsulation errors.

    Status decisions in callers should match on the variant type, never on
    ``str(err)`` or ``Display`` output. The typed variants are module-level
    subclasses below; ``issubclass(EomTruncated, EomError)`` holds.
    """


class EomTruncated(EomError):
    """The buffer is too short to contain the layer's header / declared payload."""


class EomNoPayload(EomError):
    """The layer is valid but carries no inner payload."""


class EomWrongLayerType(EomError):
    """The bytes do not start with the layer the caller declared."""


class EomMalformedLayer(EomError):
    """The layer's header is structurally present but inconsistent."""


class EomBadFrame(EomError):
    """The outer Ethernet / IP transport frame failed its structural check."""


# ---------------------------------------------------------------------------
# Layer registry
# ---------------------------------------------------------------------------


class Layer(Enum):
    """A configurable inner layer in the EoMacca stack.

    The fixed outer transport (outer Ethernet + outer IP) is *not* a
    ``Layer`` member; it is applied by :class:`EoMaccaStack` outside the
    configurable list. All ``Layer`` members can appear any number of
    times in arbitrary positions inside the configurable stack.

    The enum value is the single character used in the v2 layer-order
    string (e.g. ``"THDtIE"`` parses to
    ``[TCP, HTTP, DNS, TCP, IP, ETHERNET]``).
    """

    ETHERNET = "E"
    IP = "I"
    TCP = "T"
    DNS = "D"
    HTTP = "H"


_LAYER_BY_CHAR: Final[dict[str, Layer]] = {m.value: m for m in Layer}


def parse_layer_order(order: str) -> list[Layer]:
    """Parse a layer-order string into a list of :class:`Layer` members.

    Each character maps to one layer (see :class:`Layer`). Lookup is
    case-insensitive so ``"THDtIE"`` and ``"thdtie"`` both parse. Whitespace
    is ignored so the string can be formatted for readability. Unknown
    characters raise ``ValueError`` naming the offending character.

    Example:
        >>> parse_layer_order("THDtIE")
        [<Layer.TCP ...>, <Layer.HTTP ...>, <Layer.DNS ...>,
         <Layer.TCP ...>, <Layer.IP ...>, <Layer.ETHERNET ...>]
    """
    parsed: list[Layer] = []
    for ch in order:
        if ch.isspace():
            continue
        layer = _LAYER_BY_CHAR.get(ch.upper())
        if layer is None:
            raise ValueError(
                f"Unknown layer character {ch!r} in layer-order string; "
                f"valid chars are {''.join(sorted(_LAYER_BY_CHAR))}"
            )
        parsed.append(layer)
    return parsed


@dataclass
class LayerConfig:
    """Per-instance configuration for a single layer in the stack.

    Only the fields relevant to ``kind`` are used; others are ignored.
    Repeated layer occurrences in a stack can carry distinct addresses by
    constructing multiple ``LayerConfig`` instances with different kwargs.
    """

    kind: Layer
    src_mac: str = OUTER_SRC_MAC
    dst_mac: str = OUTER_DST_MAC
    src_ip: str = INNER_SRC_IP
    dst_ip: str = INNER_DST_IP
    src_port: int = INNER_SRC_PORT
    dst_port: int = INNER_DST_PORT
    proto: int = 6  # TCP
    tcp_flags: str = "PA"
    tcp_seq: int = 1000
    tcp_ack: int = 1000


# ---------------------------------------------------------------------------
# Default v1-compatible stack ordering
# ---------------------------------------------------------------------------

#: The v1 wire format corresponds to this decapsulation order (outer -> inner).
#:
#: ``ETHERNET`` here is the *inner* Ethernet frame (layer 1 of the RFC);
#: the outer Ethernet + outer IP are applied as a fixed wrap by
#: :class:`EoMaccaStack` and are not part of this list. The default
#: sequence reproduces v1's ``"ETHDtie"`` wire bytes byte-for-byte.
DEFAULT_LAYER_ORDER: Final[tuple[Layer, ...]] = (
    Layer.TCP,  # outer TCP (carries the outer IP envelope)
    Layer.HTTP,  # HTTP POST wraps DNS
    Layer.DNS,  # DNS TXT wraps base64(inner TCP)
    Layer.TCP,  # inner TCP (carries inner IP envelope)
    Layer.IP,  # inner IP wraps inner Ethernet
    Layer.ETHERNET,  # inner Ethernet wraps payload
)


def default_layer_configs() -> list[LayerConfig]:
    """Return a fresh copy of the v1-compatible default layer config.

    The outer configurable layer (``Layer.TCP``) uses outer addresses; the
    inner ``Layer.TCP`` and ``Layer.IP`` use inner addresses. This mirrors
    v1's hardcoded usage.
    """

    return [
        LayerConfig(
            kind=Layer.TCP,
            src_ip=OUTER_SRC_IP,
            dst_ip=OUTER_DST_IP,
            src_port=OUTER_SRC_PORT,
            dst_port=OUTER_DST_PORT,
            tcp_seq=2000,
            tcp_ack=2000,
        ),
        LayerConfig(kind=Layer.HTTP),
        LayerConfig(kind=Layer.DNS),
        LayerConfig(
            kind=Layer.TCP,
            src_ip=INNER_SRC_IP,
            dst_ip=INNER_DST_IP,
            src_port=INNER_SRC_PORT,
            dst_port=INNER_DST_PORT,
            tcp_seq=1000,
            tcp_ack=1000,
        ),
        LayerConfig(
            kind=Layer.IP,
            src_ip=INNER_SRC_IP,
            dst_ip=INNER_DST_IP,
            proto=6,
        ),
        LayerConfig(
            kind=Layer.ETHERNET,
            src_mac=OUTER_SRC_MAC,
            dst_mac=OUTER_DST_MAC,
        ),
    ]


# ---------------------------------------------------------------------------
# The wrangler: holds layer-independent config and exposes per-layer ops
# ---------------------------------------------------------------------------


@dataclass
class EomWrangler:
    """Encapsulate / decapsulate individual EoMacca layers.

    Every encap function takes ``bytes`` and returns ``bytes``; every decap
    function takes the bytes of *exactly one layer* (as bounded by the
    enclosing layer) and returns the inner payload bytes. No function here
    greedily parses past its own layer boundary.
    """

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

    # --- per-layer encap ---------------------------------------------------

    def encapsulate_ethernet(
        self, payload: bytes, *, src_mac: str, dst_mac: str
    ) -> bytes:
        """Wrap ``payload`` in a single 14-byte Ethernet II header."""
        return bytes(Ether(src=src_mac, dst=dst_mac) / Raw(load=payload))

    def encapsulate_ip(
        self, payload: bytes, *, src_ip: str, dst_ip: str, proto: int = 6
    ) -> bytes:
        """Wrap ``payload`` in a single IPv4 packet (no TCP)."""
        return bytes(IP(src=src_ip, dst=dst_ip, proto=proto) / Raw(load=payload))

    def encapsulate_tcp(
        self,
        payload: bytes,
        *,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        flags: str = "PA",
        seq: int = 1000,
        ack: int = 1000,
    ) -> bytes:
        """Wrap ``payload`` in an IP+TCP envelope (a TCP segment routed in IP).

        Conceptually a ``Layer.TCP`` carries both an IP and a TCP header,
        matching how TCP only exists nested inside IP. ``decapsulate_tcp``
        is the inverse: it peels both.
        """
        return bytes(
            IP(src=src_ip, dst=dst_ip)
            / TCP(
                sport=src_port,
                dport=dst_port,
                flags=flags,
                seq=seq,
                ack=ack,
            )
            / Raw(load=payload)
        )

    def encapsulate_dns(self, payload: bytes) -> bytes:
        """Wrap ``payload`` (base64-encoded) in a DNS TXT response message."""
        encoded = base64.b64encode(payload).decode("ascii")

        chunk_size = 250
        chunks = [
            encoded[i : i + chunk_size] for i in range(0, len(encoded), chunk_size)
        ]

        dns_msg = dnslib.DNSRecord(
            dnslib.DNSHeader(qr=1, aa=1, rd=1, ra=1),
            q=dnslib.DNSQuestion(self.dns_domain, dnslib.QTYPE.TXT),
        )
        dns_msg.add_answer(
            dnslib.RR(
                rname=self.dns_domain,
                rtype=dnslib.QTYPE.TXT,
                rclass=1,
                ttl=0,
                rdata=dnslib.TXT(chunks),
            )
        )
        return dns_msg.pack()  # type: ignore[no-any-return]

    def encapsulate_http(self, payload: bytes) -> bytes:
        """Wrap ``payload`` in a minimal HTTP/1.1 POST request."""
        head = (
            f"POST {self.http_path} HTTP/1.1\r\n"
            f"Host: {self.http_host}\r\n"
            f"Content-Type: {self.http_content_type}\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"User-Agent: {self.user_agent}\r\n"
            f"Cookie: overhead=yes\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode("ascii")
        return head + payload

    # --- per-layer decap ---------------------------------------------------

    def decapsulate_ethernet(self, layer_bytes: bytes) -> bytes:
        """Strip a 14-byte Ethernet II header and return the payload.

        Ethernet has no length field of its own: it relies on the enclosing
        layer's boundary (e.g. the outer IP packet's Total Length) to know
        where the payload ends. The caller must therefore pass only the
        bytes that belong to this Ethernet frame.
        """
        if len(layer_bytes) < MIN_ETH_HEADER:
            raise EomTruncated(
                f"Ethernet frame too short: {len(layer_bytes)} bytes, "
                f"minimum is {MIN_ETH_HEADER}"
            )
        return layer_bytes[MIN_ETH_HEADER:]

    def decapsulate_ip(self, layer_bytes: bytes) -> bytes:
        """Strip an IPv4 header and return the IP payload.

        Uses the IP Total Length field to bound the payload, so trailing
        bytes (if any) are discarded. Non-greedy: never reads past
        Total Length.
        """
        if len(layer_bytes) < MIN_IP_HEADER:
            raise EomTruncated(
                f"IP packet too short: {len(layer_bytes)} bytes, "
                f"minimum is {MIN_IP_HEADER}"
            )
        version = layer_bytes[0] >> 4
        if version != 4:
            raise EomWrongLayerType(
                f"Expected IPv4 header (version 4), got version {version}"
            )
        ihl_words = layer_bytes[0] & 0x0F
        if ihl_words < 5:
            raise EomMalformedLayer(f"IP IHL too small: {ihl_words} 32-bit words")
        ip_hdr_len = ihl_words * 4
        if len(layer_bytes) < ip_hdr_len:
            raise EomTruncated(
                f"IP header truncated: declared {ip_hdr_len} bytes, "
                f"got {len(layer_bytes)}"
            )
        total_length = int.from_bytes(layer_bytes[2:4], "big")
        if total_length < ip_hdr_len:
            raise EomMalformedLayer(
                f"IP Total Length {total_length} smaller than IHL {ip_hdr_len}"
            )
        if total_length > len(layer_bytes):
            raise EomTruncated(
                f"IP Total Length {total_length} exceeds "
                f"available {len(layer_bytes)} bytes"
            )
        payload = layer_bytes[ip_hdr_len:total_length]
        if not payload:
            raise EomNoPayload("IP packet has no payload")
        return payload

    def decapsulate_tcp(self, layer_bytes: bytes) -> bytes:
        """Strip an IP+TCP envelope and return the TCP payload.

        A ``Layer.TCP`` is conceptually a TCP segment routed in IP: both
        headers belong to this layer. The IP Total Length fields bounds the
        TCP segment; the TCP Data Offset strips the TCP header. Non-greedy.
        """
        if len(layer_bytes) < MIN_IP_HEADER + MIN_TCP_HEADER:
            raise EomTruncated(
                f"TCP/IP segment too short: {len(layer_bytes)} bytes, "
                f"minimum is {MIN_IP_HEADER + MIN_TCP_HEADER}"
            )
        version = layer_bytes[0] >> 4
        if version != 4:
            raise EomWrongLayerType(
                f"Expected IPv4 header (version 4), got version {version}"
            )
        ihl_words = layer_bytes[0] & 0x0F
        if ihl_words < 5:
            raise EomMalformedLayer(f"IP IHL too small: {ihl_words} 32-bit words")
        ip_hdr_len = ihl_words * 4
        if len(layer_bytes) < ip_hdr_len:
            raise EomTruncated(
                f"IP header truncated: declared {ip_hdr_len} bytes, "
                f"got {len(layer_bytes)}"
            )
        total_length = int.from_bytes(layer_bytes[2:4], "big")
        if total_length < ip_hdr_len + MIN_TCP_HEADER:
            raise EomMalformedLayer(
                f"IP Total Length {total_length} too small for IP+TCP headers"
            )
        if total_length > len(layer_bytes):
            raise EomTruncated(
                f"IP Total Length {total_length} exceeds "
                f"available {len(layer_bytes)} bytes"
            )
        proto = layer_bytes[9]
        if proto != 6:
            raise EomWrongLayerType(f"Expected TCP (proto 6), got proto {proto}")

        tcp = layer_bytes[ip_hdr_len:total_length]
        if len(tcp) < MIN_TCP_HEADER:
            raise EomTruncated(f"TCP header truncated: {len(tcp)} bytes in segment")
        data_offset_words = tcp[12] >> 4
        if data_offset_words < 5:
            raise EomMalformedLayer(
                f"TCP Data Offset too small: {data_offset_words} 32-bit words"
            )
        tcp_hdr_len = data_offset_words * 4
        if len(tcp) < tcp_hdr_len:
            raise EomTruncated(
                f"TCP header truncated: declared {tcp_hdr_len} bytes, got {len(tcp)}"
            )
        payload = tcp[tcp_hdr_len:]
        if not payload:
            raise EomNoPayload("TCP segment has no payload")
        return payload

    def decapsulate_dns(self, layer_bytes: bytes) -> bytes:
        """Parse a DNS message, find the first TXT answer, base64-decode it.

        A DNS message is self-delimiting via its record RDLENGTH fields, so
        ``layer_bytes`` should contain exactly the DNS message.
        """
        if len(layer_bytes) < 12:
            raise EomTruncated(
                f"DNS message too short: {len(layer_bytes)} bytes, minimum is 12"
            )
        try:
            record = dnslib.DNSRecord.parse(layer_bytes)
        except Exception as e:
            raise EomMalformedLayer(f"Failed to parse DNS message: {e}") from e

        if not record.rr:
            raise EomNoPayload("DNS message has no answer records")

        txt = record.rr[0]
        if txt.rtype != dnslib.QTYPE.TXT:
            raise EomWrongLayerType(
                f"Expected DNS TXT record, got {dnslib.QTYPE[txt.rtype]}"
            )

        rdata = txt.rdata
        if hasattr(rdata, "data"):
            joined = "".join(
                chunk.decode("ascii") if isinstance(chunk, bytes) else chunk
                for chunk in rdata.data
            )
        else:
            joined = str(rdata)

        if not joined:
            raise EomNoPayload("DNS TXT record is empty")

        try:
            return base64.b64decode(joined)
        except Exception as e:
            raise EomMalformedLayer(
                f"Failed to base64-decode DNS TXT payload: {e}"
            ) from e

    def decapsulate_http(self, layer_bytes: bytes) -> bytes:
        """Parse an HTTP request, extract exactly Content-Length bytes of body.

        Non-greedy: reads Content-Length from the headers and returns exactly
        the body bytes, ignoring any trailing bytes (which would belong to a
        sibling layer, not this one).
        """
        if len(layer_bytes) < 16:
            raise EomTruncated(f"HTTP message too short: {len(layer_bytes)} bytes")
        header_end = layer_bytes.find(b"\r\n\r\n")
        if header_end == -1:
            raise EomMalformedLayer(
                "HTTP message has no header terminator (\\r\\n\\r\\n)"
            )
        headers = layer_bytes[:header_end].split(b"\r\n")
        # First line is the request/status line; skip it.
        content_length: int | None = None
        for line in headers[1:]:
            lower = line.lower()
            if lower.startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError as e:
                    raise EomMalformedLayer(
                        f"Invalid Content-Length header: {e}"
                    ) from e
                break
        body_start = header_end + 4
        body = layer_bytes[body_start:]
        if content_length is None:
            # Fall back to "all remaining bytes" if there is no
            # Content-Length header (matches v1's behaviour for variable
            # bodies). This is non-greedy only when the enclosing layer has
            # already bounded us to exactly the HTTP body.
            if not body:
                raise EomNoPayload("HTTP message has no body")
            return body
        if content_length < 0:
            raise EomMalformedLayer(f"Negative Content-Length: {content_length}")
        if len(body) < content_length:
            raise EomTruncated(
                f"HTTP body truncated: Content-Length declares "
                f"{content_length} bytes, got {len(body)}"
            )
        if content_length == 0:
            raise EomNoPayload("HTTP message has empty body")
        return body[:content_length]

    # --- fixed outer transport (Ethernet only; the outer IP is contributed
    #     by the outermost configurable Layer.TCP / Layer.IP) ---------------

    def encapsulate_outer_ethernet(
        self, payload: bytes, *, src_mac: str, dst_mac: str
    ) -> bytes:
        """Wrap an already-wrapped IP packet in the outer Ethernet frame.

        ``payload`` must begin with an IPv4 header (i.e. it is the output of
        the outermost configurable ``Layer.TCP`` or ``Layer.IP``). EtherType
        is set explicitly to 0x0800 (IPv4) rather than having scapy infer it,
        because the payload is passed as opaque bytes (not a parsed scapy
        ``IP`` layer) so the inference would not fire.
        """
        return bytes(Ether(src=src_mac, dst=dst_mac, type=0x0800) / Raw(load=payload))

    def decapsulate_outer_ethernet(self, frame: bytes) -> bytes:
        """Strip the fixed outer Ethernet frame and return the IP packet.

        Does *not* check EtherType — by v2 contract the next byte after the
        14-byte Ethernet header is always an IPv4 header. The payload (which
        is the entire IP packet, bounded by the frame size on the wire) is
        returned for the configurable layer stack to consume.
        """
        if len(frame) < MIN_ETH_HEADER:
            raise EomBadFrame(
                f"Outer Ethernet frame too short: {len(frame)} bytes, "
                f"minimum is {MIN_ETH_HEADER}"
            )
        return frame[MIN_ETH_HEADER:]

    # --- per-Layer dispatch helpers ----------------------------------------

    def encapsulate_layer(self, cfg: LayerConfig, payload: bytes) -> bytes:
        """Dispatch to the per-layer encap function based on ``cfg.kind``."""
        kind = cfg.kind
        if kind is Layer.ETHERNET:
            return self.encapsulate_ethernet(
                payload, src_mac=cfg.src_mac, dst_mac=cfg.dst_mac
            )
        if kind is Layer.IP:
            return self.encapsulate_ip(
                payload, src_ip=cfg.src_ip, dst_ip=cfg.dst_ip, proto=cfg.proto
            )
        if kind is Layer.TCP:
            return self.encapsulate_tcp(
                payload,
                src_ip=cfg.src_ip,
                dst_ip=cfg.dst_ip,
                src_port=cfg.src_port,
                dst_port=cfg.dst_port,
                flags=cfg.tcp_flags,
                seq=cfg.tcp_seq,
                ack=cfg.tcp_ack,
            )
        if kind is Layer.HTTP:
            return self.encapsulate_http(payload)
        if kind is Layer.DNS:
            return self.encapsulate_dns(payload)
        raise ValueError(f"Unknown layer kind: {kind!r}")

    def decapsulate_layer(self, cfg: LayerConfig, layer_bytes: bytes) -> bytes:
        """Dispatch to the per-layer decap function based on ``cfg.kind``.

        Only the ``kind`` field of ``cfg`` is used; decap relies purely on
        the bytes' content for parsing.
        """
        kind = cfg.kind
        if kind is Layer.ETHERNET:
            return self.decapsulate_ethernet(layer_bytes)
        if kind is Layer.IP:
            return self.decapsulate_ip(layer_bytes)
        if kind is Layer.TCP:
            return self.decapsulate_tcp(layer_bytes)
        if kind is Layer.HTTP:
            return self.decapsulate_http(layer_bytes)
        if kind is Layer.DNS:
            return self.decapsulate_dns(layer_bytes)
        raise ValueError(f"Unknown layer kind: {kind!r}")
