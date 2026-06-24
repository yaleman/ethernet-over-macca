"""Integration tests for EoMacca protocol - full end-to-end testing."""

import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from src.client.tcp_client import TCPClient
from src.protocol_stack import EoMaccaStack
from src.server.tcp_server import TCPServer


@pytest.mark.parametrize("tcp_server", ["echo"], indirect=True)
def test_echo_integration(tcp_server: TCPServer) -> None:
    """Test full echo round-trip through server."""
    client = TCPClient(host="127.0.0.1", port=tcp_server.port)

    message = "Integration test message"
    response = client.echo(message)

    assert response == message


@pytest.mark.parametrize("tcp_server", ["ping"], indirect=True)
def test_ping_integration(tcp_server: TCPServer) -> None:
    """Test ping functionality through server."""
    client = TCPClient(host="127.0.0.1", port=tcp_server.port)

    rtts = client.ping(count=3)

    assert len(rtts) == 3
    assert all(rtt > 0 for rtt in rtts)
    assert all(rtt < 1000 for rtt in rtts)


@pytest.mark.parametrize("tcp_server", ["file"], indirect=True)
def test_file_transfer_integration(tcp_server: TCPServer) -> None:
    """Test file transfer through server."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("Test file for integration testing")
        test_file_path = Path(f.name)

    try:
        client = TCPClient(host="127.0.0.1", port=tcp_server.port)
        response = client.send_file(test_file_path)

        assert "received" in response.lower()
        assert test_file_path.name in response
    finally:
        test_file_path.unlink()


def test_multiple_clients() -> None:
    """Test server handling multiple clients concurrently."""
    port = 19998
    server = TCPServer(host="127.0.0.1", port=port, mode="echo")

    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    clients = [TCPClient(host="127.0.0.1", port=port) for _ in range(3)]

    results = []
    threads = []

    def send_message(client: TCPClient, msg: str) -> None:
        result = client.echo(msg)
        results.append(result)

    for i, client in enumerate(clients):
        t = threading.Thread(target=send_message, args=(client, f"Message {i}"))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=5)

    assert len(results) == 3
    assert "Message 0" in results
    assert "Message 1" in results
    assert "Message 2" in results

    server.running = False
    time.sleep(0.1)


def test_large_payload() -> None:
    """Test sending large payload through protocol stack."""
    port = 19997
    server = TCPServer(host="127.0.0.1", port=port, mode="echo")

    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    client = TCPClient(host="127.0.0.1", port=port)

    large_message = "X" * 10000
    response = client.echo(large_message)

    assert response == large_message

    server.running = False
    time.sleep(0.1)


def test_binary_payload() -> None:
    """Test sending binary data through protocol."""
    port = 19996
    server = TCPServer(host="127.0.0.1", port=port, mode="echo")

    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    stack = EoMaccaStack()
    binary_data = bytes(range(256))

    packet = stack.encapsulate(binary_data)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(("127.0.0.1", port))
        sock.sendall(packet)
        response_packet = sock.recv(65536)

    response_data = stack.decapsulate(response_packet)
    assert response_data == binary_data

    server.running = False
    time.sleep(0.1)


def test_connection_error_handling() -> None:
    """Test client behavior when server is not available."""
    client = TCPClient(host="127.0.0.1", port=65432)

    with pytest.raises(ConnectionRefusedError):
        client.echo("This should fail")


def test_protocol_overhead_statistics() -> None:
    """Test overhead calculation accuracy."""
    stack = EoMaccaStack()

    test_sizes = [10, 50, 100, 500, 1000]

    for size in test_sizes:
        payload = b"X" * size
        stats = stack.get_overhead_stats(payload)

        assert stats["payload_size"] == size
        assert stats["total_size"] > size
        assert stats["header_size"] == stats["total_size"] - size
        assert stats["overhead_ratio"] > 0
        assert 0 < stats["efficiency_percent"] < 100

        if size >= 100:
            assert stats["efficiency_percent"] > 15


class TestMalformedPackets:
    """Test handling of malformed packets."""

    def test_empty_packet(self) -> None:
        """Test decapsulation of empty packet."""
        stack = EoMaccaStack()

        with pytest.raises(Exception):
            stack.decapsulate(b"")

    def test_truncated_ethernet(self) -> None:
        """Test decapsulation of truncated Ethernet frame."""
        stack = EoMaccaStack()

        with pytest.raises(Exception):
            stack.decapsulate(b"\x00" * 10)

    def test_random_bytes(self) -> None:
        """Test decapsulation of random bytes."""
        stack = EoMaccaStack()

        with pytest.raises(Exception):
            stack.decapsulate(b"\xff" * 100)

    def test_partial_valid_packet(self) -> None:
        """Test decapsulation of partially valid packet."""
        stack = EoMaccaStack()
        payload = b"Test payload"
        valid_packet = stack.encapsulate(payload)

        truncated = valid_packet[: len(valid_packet) // 2]

        with pytest.raises(Exception):
            stack.decapsulate(truncated)

    def test_invalid_ip_in_tcp(self) -> None:
        """Test handling of TCP segment with invalid IP payload."""
        from src.encapsulation import decapsulate_tcp_to_ip

        with pytest.raises(ValueError, match="too short"):
            decapsulate_tcp_to_ip(b"\x00" * 10)

    def test_invalid_tcp_in_dns(self) -> None:
        """Test handling of DNS message with invalid TXT record type."""
        from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A

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

        from src.encapsulation import decapsulate_dns_to_tcp

        with pytest.raises(ValueError, match="Expected TXT record"):
            decapsulate_dns_to_tcp(dns_msg.pack())

    def test_empty_dns_txt(self) -> None:
        """Test handling of DNS message with no answer records."""
        from dnslib import DNSRecord, DNSHeader

        dns_msg = DNSRecord(DNSHeader(qr=1, aa=1, rd=1, ra=1))

        from src.encapsulation import decapsulate_dns_to_tcp

        with pytest.raises(ValueError, match="no answer records"):
            decapsulate_dns_to_tcp(dns_msg.pack())

    def test_malformed_http_headers(self) -> None:
        """Test handling of malformed HTTP headers."""
        from src.encapsulation import decapsulate_http_to_dns

        with pytest.raises(ValueError, match="too short"):
            decapsulate_http_to_dns(b"short")

        with pytest.raises(ValueError, match="no header terminator"):
            decapsulate_http_to_dns(b"GET / HTTP/1.1\r\nno terminator")

    def test_empty_http_body(self) -> None:
        """Test handling of HTTP with empty body."""
        from src.encapsulation import decapsulate_http_to_dns

        http_msg = (
            b"GET / HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )

        with pytest.raises(ValueError, match="no body"):
            decapsulate_http_to_dns(http_msg)

    def test_concurrent_malformed_packets(self) -> None:
        """Test server handling of concurrent malformed packets."""
        port = 19995
        server = TCPServer(host="127.0.0.1", port=port, mode="echo")

        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()
        time.sleep(0.5)

        results = []

        def send_bad_packet(data: bytes) -> None:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(2.0)
                    sock.connect(("127.0.0.1", port))
                    sock.sendall(data)
                    response = sock.recv(65536)
                    results.append(("success", len(response)))
            except Exception as e:
                results.append(("error", str(e)))

        bad_packets = [
            b"",
            b"\x00" * 10,
            b"\xff" * 100,
            b"not a valid packet at all",
        ]

        threads = []
        for packet in bad_packets:
            t = threading.Thread(target=send_bad_packet, args=(packet,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=5)

        assert len(results) == len(bad_packets)

        server.running = False
        time.sleep(0.1)
