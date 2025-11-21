"""Tests for the EoMacca protocol stack."""

import pytest
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from src.protocol_stack import EoMaccaStack
from src.encapsulation import (
    encapsulate_ethernet_in_ip,
    encapsulate_ip_in_tcp,
    encapsulate_tcp_in_dns,
    encapsulate_dns_in_http,
    decapsulate_http_to_dns,
    decapsulate_dns_to_tcp,
)


class TestEncapsulation:
    """Test individual encapsulation layers."""

    def test_ethernet_in_ip(self) -> None:
        """Test Ethernet frame encapsulation in IP."""
        eth_frame = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / Raw(
            load=b"test payload"
        )
        eth_bytes = bytes(eth_frame)

        ip_packet = encapsulate_ethernet_in_ip(eth_bytes)

        assert len(ip_packet) > len(eth_bytes)
        assert isinstance(ip_packet, bytes)

    def test_ip_in_tcp(self) -> None:
        """Test IP packet encapsulation in TCP."""
        ip_data = b"fake IP packet data"
        tcp_segment = encapsulate_ip_in_tcp(ip_data)

        assert len(tcp_segment) > len(ip_data)
        assert isinstance(tcp_segment, bytes)

    def test_tcp_in_dns(self) -> None:
        """Test TCP segment encapsulation in DNS."""
        tcp_data = b"fake TCP segment data"
        dns_message = encapsulate_tcp_in_dns(tcp_data)

        assert len(dns_message) > 0
        assert isinstance(dns_message, (bytes, bytearray))

    def test_dns_in_http(self) -> None:
        """Test DNS message encapsulation in HTTP."""
        dns_data = b"fake DNS message"
        http_request = encapsulate_dns_in_http(dns_data)

        assert b"POST" in http_request
        assert b"HTTP/1.1" in http_request
        assert b"Content-Type: application/dns-message" in http_request
        assert dns_data in http_request


class TestDecapsulation:
    """Test individual decapsulation layers."""

    def test_http_to_dns(self) -> None:
        """Test DNS extraction from HTTP."""
        dns_data = b"fake DNS message"
        http_request = encapsulate_dns_in_http(dns_data)

        extracted_dns = decapsulate_http_to_dns(http_request)
        assert extracted_dns == dns_data

    def test_http_to_dns_invalid(self) -> None:
        """Test HTTP decapsulation with invalid data."""
        with pytest.raises(ValueError):
            decapsulate_http_to_dns(b"not an HTTP message")

    def test_dns_roundtrip(self) -> None:
        """Test DNS encapsulation and decapsulation roundtrip."""
        original_tcp = b"test TCP data for DNS roundtrip"

        dns_msg = encapsulate_tcp_in_dns(original_tcp)
        recovered_tcp = decapsulate_dns_to_tcp(dns_msg)

        assert recovered_tcp == original_tcp


class TestProtocolStack:
    """Test the complete protocol stack."""

    def test_basic_encapsulation(self) -> None:
        """Test basic payload encapsulation."""
        stack = EoMaccaStack()
        payload = b"Hello, EoMacca!"

        encapsulated = stack.encapsulate(payload)

        assert len(encapsulated) > len(payload)
        assert isinstance(encapsulated, bytes)

    def test_encapsulation_decapsulation_roundtrip(self) -> None:
        """Test full encapsulation and decapsulation cycle."""
        stack = EoMaccaStack()
        original_payload = b"This is a test payload for EoMacca protocol"

        # Encapsulate
        encapsulated = stack.encapsulate(original_payload)

        # Decapsulate
        recovered_payload = stack.decapsulate(encapsulated)

        # Verify
        assert recovered_payload == original_payload

    def test_different_payload_sizes(self) -> None:
        """Test encapsulation with various payload sizes."""
        stack = EoMaccaStack()
        test_sizes = [1, 10, 100, 500, 1000]

        for size in test_sizes:
            payload = b"X" * size
            encapsulated = stack.encapsulate(payload)
            recovered = stack.decapsulate(encapsulated)
            assert recovered == payload, f"Failed for size {size}"

    def test_empty_payload(self) -> None:
        """Test handling of empty payload."""
        stack = EoMaccaStack()
        payload = b""

        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload

    def test_binary_payload(self) -> None:
        """Test with binary payload containing all byte values."""
        stack = EoMaccaStack()
        payload = bytes(range(256))

        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload

    def test_overhead_stats(self) -> None:
        """Test overhead statistics calculation."""
        stack = EoMaccaStack()
        payload = b"Test payload for stats"

        stats = stack.get_overhead_stats(payload)

        assert stats["payload_size"] == len(payload)
        assert stats["total_size"] > stats["payload_size"]
        assert stats["header_size"] == stats["total_size"] - stats["payload_size"]
        assert stats["overhead_ratio"] > 0
        assert 0 < stats["efficiency_percent"] < 100

    def test_overhead_increases_with_small_payloads(self) -> None:
        """Test that overhead ratio is worse for smaller payloads."""
        stack = EoMaccaStack()

        stats_small = stack.get_overhead_stats(b"X" * 10)
        stats_large = stack.get_overhead_stats(b"X" * 1000)

        # Larger payloads should have better efficiency
        assert stats_large["efficiency_percent"] > stats_small["efficiency_percent"]

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

    def test_decapsulate_invalid_ethernet(self) -> None:
        """Test decapsulation with invalid Ethernet frame."""
        stack = EoMaccaStack()

        with pytest.raises(Exception):  # Could be various exceptions from scapy
            stack.decapsulate(b"not a valid packet")

    def test_very_long_payload(self) -> None:
        """Test with a very long payload."""
        stack = EoMaccaStack()
        payload = b"A" * 10000  # 10KB payload

        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload

    def test_unicode_payload(self) -> None:
        """Test with Unicode data encoded as bytes."""
        stack = EoMaccaStack()
        unicode_text = "Hello, 世界! 🌍"
        payload = unicode_text.encode("utf-8")

        encapsulated = stack.encapsulate(payload)
        recovered = stack.decapsulate(encapsulated)

        assert recovered == payload
        assert recovered.decode("utf-8") == unicode_text
