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
    assert all(rtt < 1000 for rtt in rtts)  # Should be under 1 second


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

    # Start server
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    # Create multiple clients
    clients = [TCPClient(host="127.0.0.1", port=port) for _ in range(3)]

    # Send messages concurrently
    results = []
    threads = []

    def send_message(client: TCPClient, msg: str) -> None:
        result = client.echo(msg)
        results.append(result)

    for i, client in enumerate(clients):
        t = threading.Thread(target=send_message, args=(client, f"Message {i}"))
        threads.append(t)
        t.start()

    # Wait for all threads
    for t in threads:
        t.join(timeout=5)

    # Verify all messages echoed correctly
    assert len(results) == 3
    assert "Message 0" in results
    assert "Message 1" in results
    assert "Message 2" in results

    # Cleanup
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

    # Send 10KB payload
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

    # Send binary data directly
    stack = EoMaccaStack()
    binary_data = bytes(range(256))  # All byte values

    packet = stack.encapsulate(binary_data)

    # Send via socket
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
    client = TCPClient(host="127.0.0.1", port=65432)  # Non-existent server

    with pytest.raises(ConnectionRefusedError):
        client.echo("This should fail")


def test_protocol_overhead_statistics() -> None:
    """Test overhead calculation accuracy."""
    stack = EoMaccaStack()

    test_sizes = [10, 50, 100, 500, 1000]

    for size in test_sizes:
        payload = b"X" * size
        stats = stack.get_overhead_stats(payload)

        # Verify statistics are correct
        assert stats["payload_size"] == size
        assert stats["total_size"] > size
        assert stats["header_size"] == stats["total_size"] - size
        assert stats["overhead_ratio"] > 0
        assert 0 < stats["efficiency_percent"] < 100

        # Larger payloads should be more efficient
        if size >= 100:
            assert stats["efficiency_percent"] > 15  # At least 15% efficient
