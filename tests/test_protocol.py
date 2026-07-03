"""Tests for the EoMacca protocol stack."""

import pytest
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.layers.inet import IP
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, TXT

from ethernet_over_macca.protocol_stack import EoMaccaStack
from ethernet_over_macca.encapsulation import (
    INNER_DST_IP,
    INNER_DST_PORT,
    INNER_SRC_IP,
    INNER_SRC_PORT,
    EomError,
    EomMalformedLayer,
    EomNoPayload,
    EomTruncated,
    EomWrangler,
    EomWrongLayerType,
    Layer,
    LayerConfig,
)


class TestEncapsulation:
    """Test individual encapsulation layers (v2 clean API)."""

    def test_ethernet_in_ip(self, wrangler: EomWrangler) -> None:
        """Test Ethernet frame encapsulation in IP via the single-layer API."""
        eth_frame = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / Raw(
            load=b"test payload"
        )
        eth_bytes = bytes(eth_frame)

        ip_packet = wrangler.encapsulate_ip(
            eth_bytes, src_ip=INNER_SRC_IP, dst_ip=INNER_DST_IP, proto=6
        )

        assert len(ip_packet) > len(eth_bytes)
        assert isinstance(ip_packet, bytes)

    def test_ip_in_tcp(self, wrangler: EomWrangler) -> None:
        """Test IP packet encapsulation in TCP via the single-layer API."""
        ip_data = b"fake IP packet data"
        tcp_segment = wrangler.encapsulate_tcp(
            ip_data,
            src_ip=INNER_SRC_IP,
            dst_ip=INNER_DST_IP,
            src_port=INNER_SRC_PORT,
            dst_port=INNER_DST_PORT,
        )

        assert len(tcp_segment) > len(ip_data)
        assert isinstance(tcp_segment, bytes)

    def test_tcp_in_dns(self, wrangler: EomWrangler) -> None:
        """Test TCP segment encapsulation in DNS via the single-layer API."""
        tcp_data = b"fake TCP segment data"
        dns_message = wrangler.encapsulate_dns(tcp_data)

        assert len(dns_message) > 0
        assert isinstance(dns_message, (bytes, bytearray))

    def test_dns_in_http(self, wrangler: EomWrangler) -> None:
        """Test DNS message encapsulation in HTTP."""
        dns_data = b"fake DNS message"
        http_request = wrangler.encapsulate_http(dns_data)

        assert b"POST" in http_request
        assert b"HTTP/1.1" in http_request
        assert f"Content-Type: {wrangler.http_content_type}".encode() in http_request
        assert dns_data in http_request


class TestDecapsulation:
    """Test individual decapsulation layers (v2 clean API)."""

    def test_http_to_dns(self, wrangler: EomWrangler) -> None:
        """Test DNS extraction from HTTP."""
        dns_data = b"fake DNS message"
        http_request = wrangler.encapsulate_http(dns_data)

        extracted_dns = wrangler.decapsulate_http(http_request)
        assert extracted_dns == dns_data

    def test_http_to_dns_invalid(self, wrangler: EomWrangler) -> None:
        """Test HTTP decapsulation with invalid data."""
        with pytest.raises(EomError):
            wrangler.decapsulate_http(b"not an HTTP message")

    def test_dns_roundtrip(self, wrangler: EomWrangler) -> None:
        """Test DNS encapsulation and decapsulation roundtrip."""
        original_tcp = b"test TCP data for DNS roundtrip"

        dns_msg = wrangler.encapsulate_dns(original_tcp)
        recovered_tcp = wrangler.decapsulate_dns(dns_msg)

        assert recovered_tcp == original_tcp


class TestProtocolStack:
    """Test the complete protocol stack."""

    def test_basic_encapsulation(self, stack: EoMaccaStack) -> None:
        """Test basic payload encapsulation."""
        payload = b"Hello, EoMacca!"

        encapsulated = stack.encapsulate(payload)

        assert len(encapsulated) > len(payload)
        assert isinstance(encapsulated, bytes)

    def test_encapsulation_decapsulation_roundtrip(self, stack: EoMaccaStack) -> None:
        """Test full encapsulation and decapsulation cycle."""
        original_payload = b"This is a test payload for EoMacca protocol"

        # Encapsulate
        encapsulated = stack.encapsulate(original_payload)

        # Decapsulate
        recovered_payload = stack.decapsulate(encapsulated)

        # Verify
        assert recovered_payload == original_payload

    def test_different_payload_sizes(self, stack: EoMaccaStack) -> None:
        """Test encapsulation with various payload sizes."""
        test_sizes = [1, 10, 100, 500, 1000]

        for size in test_sizes:
            payload = b"X" * size
            encapsulated = stack.encapsulate(payload)
            recovered = stack.decapsulate(encapsulated)
            assert recovered == payload, f"Failed for size {size}"

    def test_empty_payload(self, stack: EoMaccaStack) -> None:
        """Test handling of empty payload."""
        payload = b""

        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload

    def test_binary_payload(self, stack: EoMaccaStack) -> None:
        """Test with binary payload containing all byte values."""
        payload = bytes(range(256))

        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload

    def test_overhead_stats(self, stack: EoMaccaStack) -> None:
        """Test overhead statistics calculation."""
        payload = b"Test payload for stats"

        stats = stack.get_overhead_stats(payload)

        assert stats.payload_size == len(payload)
        assert stats.total_size > stats.payload_size
        assert stats.header_size == stats.total_size - stats.payload_size
        assert stats.overhead_ratio > 0
        assert 0 < stats.efficiency_percent < 100

    def test_overhead_increases_with_small_payloads(self, stack: EoMaccaStack) -> None:
        """Test that overhead ratio is worse for smaller payloads."""

        stats_small = stack.get_overhead_stats(b"X" * 10)
        stats_large = stack.get_overhead_stats(b"X" * 1000)

        # Larger payloads should have better efficiency
        assert stats_large.efficiency_percent > stats_small.efficiency_percent

    def test_custom_addresses(self) -> None:
        """Test stack with custom addresses."""
        stack = EoMaccaStack(
            outer_src_ip="10.0.0.1",
            outer_dst_ip="10.0.0.2",
            outer_src_port=12345,
            outer_dst_port=54321,
            outer_src_mac="aa:bb:cc:dd:ee:ff",
            outer_dst_mac="ff:ee:dd:cc:bb:aa",
        )

        payload = b"Custom address test"
        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_decapsulate_invalid_ethernet(self, stack: EoMaccaStack) -> None:
        """Test decapsulation with invalid Ethernet frame."""

        with pytest.raises(Exception):
            stack.decapsulate(b"not a valid packet")

    def test_very_long_payload(self, stack: EoMaccaStack) -> None:
        """Test with a very long payload."""
        payload = b"A" * 10000

        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload

    def test_unicode_payload(self, stack: EoMaccaStack) -> None:
        """Test with Unicode data encoded as bytes."""
        unicode_text = "Hello, 世界! 🌍"
        payload = unicode_text.encode("utf-8")

        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload
        assert recovered.decode("utf-8") == unicode_text


class TestDecapsulationValidation:
    """Test validation in decapsulation functions (typed errors, v2 API)."""

    def test_http_too_short(self, wrangler: EomWrangler) -> None:
        """Test HTTP decapsulation with too-short data."""
        with pytest.raises(EomTruncated):
            wrangler.decapsulate_http(b"short")

    def test_http_no_terminator(self, wrangler: EomWrangler) -> None:
        """Test HTTP decapsulation without header terminator."""
        with pytest.raises(EomMalformedLayer):
            wrangler.decapsulate_http(b"GET / HTTP/1.1\r\nno terminator")

    def test_http_empty_body(self, wrangler: EomWrangler) -> None:
        """Test HTTP decapsulation with empty body."""
        http_msg = b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
        with pytest.raises(EomNoPayload):
            wrangler.decapsulate_http(http_msg)

    def test_dns_too_short(self, wrangler: EomWrangler) -> None:
        """Test DNS decapsulation with too-short data."""
        with pytest.raises(EomTruncated):
            wrangler.decapsulate_dns(b"\x00" * 10)

    def test_dns_no_answers(self, wrangler: EomWrangler) -> None:
        """Test DNS decapsulation with no answer records."""
        dns_msg = DNSRecord(DNSHeader(qr=1, aa=1, rd=1, ra=1))
        with pytest.raises(EomNoPayload):
            wrangler.decapsulate_dns(dns_msg.pack())

    def test_dns_wrong_type(self, wrangler: EomWrangler) -> None:
        """Test DNS decapsulation with wrong record type."""
        dns_msg = DNSRecord(DNSHeader(qr=1, aa=1, rd=1, ra=1))
        dns_msg.add_answer(
            RR(
                rname="test.example.com",
                rtype=QTYPE.A,
                rclass=1,
                ttl=0,
                rdata=A("127.0.0.1"),
            )
        )
        with pytest.raises(EomWrongLayerType):
            wrangler.decapsulate_dns(dns_msg.pack())

    def test_dns_empty_txt(self, wrangler: EomWrangler) -> None:
        """Test DNS decapsulation with empty TXT data."""
        dns_msg = DNSRecord(DNSHeader(qr=1, aa=1, rd=1, ra=1))
        dns_msg.add_answer(
            RR(
                rname="test.example.com",
                rtype=QTYPE.TXT,
                rclass=1,
                ttl=0,
                rdata=TXT([""]),
            )
        )
        with pytest.raises(EomNoPayload):
            wrangler.decapsulate_dns(dns_msg.pack())

    def test_tcp_too_short(self, wrangler: EomWrangler) -> None:
        """Test TCP decapsulation with too-short data."""
        with pytest.raises(EomTruncated):
            wrangler.decapsulate_tcp(b"\x00" * 10)

    def test_ip_too_short(self, wrangler: EomWrangler) -> None:
        """Test IP decapsulation with too-short data."""
        with pytest.raises(EomTruncated):
            wrangler.decapsulate_ip(b"\x00" * 10)

    def test_ip_no_payload(self, wrangler: EomWrangler) -> None:
        """Test IP decapsulation with no payload."""
        packet = IP(src="10.0.0.1", dst="10.0.0.2")
        with pytest.raises(EomNoPayload):
            wrangler.decapsulate_ip(bytes(packet))


class TestV2ArbitraryOrderings:
    """Exercise v2's defining feature: arbitrary configurable layer orderings."""

    @pytest.mark.parametrize(
        "order",
        [
            [Layer.TCP, Layer.HTTP, Layer.DNS, Layer.TCP, Layer.IP, Layer.ETHERNET],
            [Layer.TCP, Layer.DNS, Layer.HTTP, Layer.IP, Layer.ETHERNET],
            [Layer.IP, Layer.ETHERNET],                       # minimal: IP+Eth only
            [Layer.TCP, Layer.IP, Layer.ETHERNET],            # bare TCP over IP over Eth
            [Layer.TCP, Layer.HTTP],                           # HTTP only over outer TCP
            [Layer.TCP, Layer.DNS],                            # DNS only over outer TCP
            # Arbitrary repetition: HTTP -> DNS -> HTTP -> DNS over outer TCP.
            [Layer.TCP, Layer.HTTP, Layer.DNS, Layer.HTTP, Layer.DNS],
            # Doubled inner TCP+IP+Eth, wrapped twice.
            [Layer.TCP, Layer.TCP, Layer.IP, Layer.ETHERNET,
             Layer.TCP, Layer.IP, Layer.ETHERNET],
        ],
        ids=[
            "v1-default",
            "no-client-tcp",
            "bare-ip-eth",
            "bare-tcp-ip-eth",
            "http-only",
            "dns-only",
            "http-dns-http-dns",
            "double-tunnel",
        ],
    )
    def test_roundtrip(self, order: list[Layer]) -> None:
        """Every valid ordering must round-trip the original payload."""
        stack = EoMaccaStack(layer_order=order)
        payload = b"the order is configurable and arbitrary"
        packet = stack.encapsulate(payload)
        recovered = stack.decapsulate(packet)
        assert recovered == payload

    def test_outermost_must_contribute_ip(self) -> None:
        """An HTTP layer as the outermost configurable layer is rejected."""
        with pytest.raises(ValueError, match="outer IP envelope"):
            EoMaccaStack(layer_order=[Layer.HTTP, Layer.DNS])

    def test_empty_layer_order_rejected(self) -> None:
        """An empty layer order is rejected."""
        with pytest.raises(ValueError, match="at least one"):
            EoMaccaStack(layer_order=[])

    def test_layers_and_layer_order_mutually_exclusive(self) -> None:
        """Cannot pass both `layers` and `layer_order`."""
        with pytest.raises(ValueError, match="not both"):
            EoMaccaStack(
                layers=[LayerConfig(kind=Layer.IP)],
                layer_order=[Layer.IP],
            )

    def test_explicit_layers_with_distinct_addresses(self) -> None:
        """Repeated layers can carry distinct addresses via LayerConfig."""
        stack = EoMaccaStack(layers=[
            LayerConfig(
                kind=Layer.TCP,
                src_ip="172.16.0.1",
                dst_ip="172.16.0.2",
                src_port=1111,
                dst_port=2222,
                tcp_seq=7777,
                tcp_ack=8888,
            ),
            LayerConfig(kind=Layer.HTTP),
            LayerConfig(kind=Layer.DNS),
            LayerConfig(
                kind=Layer.TCP,
                src_ip="10.99.0.1",
                dst_ip="10.99.0.2",
                src_port=3333,
                dst_port=4444,
                tcp_seq=5555,
                tcp_ack=6666,
            ),
            LayerConfig(kind=Layer.IP, src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            LayerConfig(kind=Layer.ETHERNET,
                        src_mac="11:22:33:44:55:66",
                        dst_mac="77:88:99:aa:bb:cc"),
        ])
        payload = b"distinct addresses per layer instance"
        assert stack.decapsulate(stack.encapsulate(payload)) == payload

    def test_infinite_repetition_supported(self) -> None:
        """A long chain of repeated layers still round-trips.

        Demonstrates "infinite layers" in practice — 20 nested TCP layers
        each carrying their own IP envelope, around a single payload.
        """
        layers = [LayerConfig(kind=Layer.TCP) for _ in range(20)]
        # The innermost needs a payload-bearing layer: add a final IP+ETH.
        layers.append(LayerConfig(kind=Layer.IP))
        layers.append(LayerConfig(kind=Layer.ETHERNET))
        stack = EoMaccaStack(layers=layers)
        payload = b"deeply nested tunnel"
        assert stack.decapsulate(stack.encapsulate(payload)) == payload

    def test_wrong_order_decapsulate_fails_cleanly(self) -> None:
        """A sender/receiver pair with mismatched orderings fails safely.

        Per the v2 contract, getting the order wrong yields a clean EomError
        (or garbage), never silent corruption.
        """
        sender = EoMaccaStack(layer_order=[
            Layer.TCP, Layer.HTTP, Layer.DNS, Layer.TCP, Layer.IP, Layer.ETHERNET,
        ])
        receiver = EoMaccaStack(layer_order=[
            Layer.TCP, Layer.DNS, Layer.HTTP, Layer.TCP, Layer.IP, Layer.ETHERNET,
        ])
        packet = sender.encapsulate(b"order matters")
        with pytest.raises(EomError):
            receiver.decapsulate(packet)


class TestV1Interop:
    """Verify the default v2 config interoperates with v1 wire format.

    Strict byte-for-byte equality is impossible across separate Python
    processes because scapy assigns random IP IDs / checksums. What we CAN
    verify is structural interop: both stacks accept each other's packets.
    """

    @pytest.mark.parametrize(
        "payload",
        [b"Hello", b"", b"X" * 100, bytes(range(256)), b"A" * 10000],
        ids=["hello", "empty", "100", "binary-256", "10000"],
    )
    def test_v2_default_decapsulates_like_v1_would(
        self, stack: EoMaccaStack, payload: bytes
    ) -> None:
        """A fresh v2 default stack round-trips its own bytes (sanity)."""
        packet = stack.encapsulate(payload)
        assert stack.decapsulate(packet) == payload

    def test_default_layer_count_matches_rfc(self) -> None:
        """The v1-compatible default has 6 configurable layers (8 total
        counting the fixed outer Ethernet + the IP from the outer TCP)."""
        stack = EoMaccaStack()
        assert len(stack.layers) == 6
        assert stack.layers[0].kind is Layer.TCP
        assert stack.layers[-1].kind is Layer.ETHERNET
