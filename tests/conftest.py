"""Shared test fixtures for EoMacca tests."""

import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Generator

import pytest

from src.protocol_stack import EoMaccaStack
from src.server.tcp_server import TCPServer
from src.server.handlers import RequestHandler


@pytest.fixture
def stack() -> EoMaccaStack:
    """Provide a fresh EoMaccaStack instance."""
    return EoMaccaStack()


@pytest.fixture
def handler() -> RequestHandler:
    """Provide a fresh RequestHandler instance."""
    return RequestHandler()


@pytest.fixture
def test_payload() -> bytes:
    """Provide standard test payload."""
    return b"Test payload for EoMacca protocol"


@pytest.fixture
def test_file(tmp_path: Path) -> Path:
    """Create a temporary test file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Test file content for EoMacca")
    return test_file


@pytest.fixture
def tcp_server(request: pytest.FixtureRequest) -> Generator[TCPServer, None, None]:
    """Start a TCP server in a thread for integration tests.

    Usage:
        @pytest.mark.parametrize("tcp_server", ["echo"], indirect=True)
        def test_with_server(tcp_server):
            # Server is running in background
            ...
    """
    mode = getattr(request, "param", "echo")

    # Find available port dynamically
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]

    server = TCPServer(host="127.0.0.1", port=port, mode=mode)  # type: ignore[arg-type]

    # Start server in thread
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()

    # Wait for server to be ready
    time.sleep(1.0)  # Give more time for server to start

    # Check if server is actually listening
    max_retries = 20
    for _ in range(max_retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            sock.connect(("127.0.0.1", port))
            sock.close()
            break
        except (ConnectionRefusedError, socket.timeout):
            time.sleep(0.2)

    # Patch the server to use our test port
    server.port = port

    yield server

    # Cleanup
    server.running = False
    time.sleep(0.2)


@pytest.fixture
def sample_ethernet_frame() -> bytes:
    """Provide a sample Ethernet frame for testing."""
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    frame = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / Raw(
        load=b"Sample payload"
    )
    return bytes(frame)


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for test outputs."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir
