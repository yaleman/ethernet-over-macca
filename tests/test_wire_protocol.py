"""Regression tests for wire-level packet encoding bugs in EoMacca."""

import struct

import pytest

from ethernet_over_macca.protocol_stack import EoMaccaStack


def send_packet(data: bytes) -> bytes:
    """Simulate the wire protocol: prepend 4-byte big-endian length."""
    return struct.pack(">I", len(data)) + data


def recv_packet(wire: bytes) -> tuple[bytes, bytes]:
    """Parse a length-prefixed packet from the wire, return (packet, remaining)."""
    length = struct.unpack(">I", wire[:4])[0]
    return wire[4 : 4 + length], wire[4 + length :]


class TestWireLengthConsistency:
    """Ensure scapy-produced bytes match their reported length on the wire.

    Previously, scapy added padding to Ether/IP/TCP layers when
    converting to bytes, which caused len() to disagree with
    bytes(). send_packet uses len() as the length prefix, but the
    actual bytes written to the socket included the padding, so the
    receiver would interpret the length prefix as huge values like
    0xAAAAAAAA.
    """

    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"x",
            b"Hello, EoMacca!",
            b"X" * 15,
            b"X" * 100,
            b"X" * 1000,
            b"X" * 10000,
            bytes(range(256)),
        ],
        ids=[
            "empty",
            "single-byte",
            "ascii-greeting",
            "15-bytes",
            "100-bytes",
            "1000-bytes",
            "10000-bytes",
            "binary-0-255",
        ],
    )
    def test_encapsulated_length_matches_bytes(
        self, payload: bytes, stack: EoMaccaStack
    ) -> None:
        """len(packet) must equal len(bytes(packet)) after encapsulation."""
        packet = stack.encapsulate(payload)
        assert len(packet) == len(bytes(packet)), (
            f"scapy padding mismatch: len()={len(packet)}, "
            f"len(bytes())={len(bytes(packet))}"
        )

    @pytest.mark.parametrize(
        "payload",
        [
            b"",
            b"test",
            b"Hello, EoMacca!",
            b"X" * 15,
            b"X" * 100,
            b"X" * 1000,
            b"X" * 10000,
            bytes(range(256)),
        ],
    )
    def test_wire_length_prefix_matches_actual_packet(
        self, payload: bytes, stack: EoMaccaStack
    ) -> None:
        """The length prefix written on the wire must match the actual bytes."""
        packet = stack.encapsulate(payload)
        wire = send_packet(packet)

        parsed, _ = recv_packet(wire)
        assert parsed == packet

    @pytest.mark.parametrize(
        "payload",
        [
            b"Hello, EoMacca!",
            b"X" * 15,
            b"X" * 100,
            bytes(range(256)),
        ],
    )
    def test_wire_roundtrip_preserves_payload(
        self, payload: bytes, stack: EoMaccaStack
    ) -> None:
        """Full wire round-trip: encapsulate -> prefix -> parse -> decapsulate."""
        packet = stack.encapsulate(payload)
        wire = send_packet(packet)
        parsed, _ = recv_packet(wire)
        recovered = stack.decapsulate(parsed)
        assert recovered == payload

    def test_no_aa_prefix_in_length_field(self, stack: EoMaccaStack) -> None:
        """Guard against the specific 0xAAAAAAAA bug from scapy padding."""
        for size in [0, 1, 15, 64, 100, 1000]:
            payload = b"X" * size
            packet = stack.encapsulate(payload)
            wire = send_packet(packet)
            length = struct.unpack(">I", wire[:4])[0]
            assert length != 0xAAAAAAAA, (
                f"Packet length prefix is 0xAAAAAAAA (size={size}): "
                f"scapy padding is leaking into the wire protocol"
            )
            assert length == len(packet)

    def test_server_response_length_matches_actual_bytes(
        self, stack: EoMaccaStack
    ) -> None:
        """Server-side response path: length prefix of the response matches its bytes."""
        payload = b"echo me"
        response_payload = payload

        response_packet = stack.encapsulate(response_payload)
        wire = send_packet(response_packet)
        parsed, remaining = recv_packet(wire)
        assert remaining == b""
        assert parsed == response_packet
        recovered = stack.decapsulate(parsed)
        assert recovered == response_payload
