"""Shared test fixtures for EoMacca tests."""

import socket
import threading
import time
from pathlib import Path
from typing import Generator

import pytest
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from ethernet_over_macca.encapsulation import Encapsulator
from ethernet_over_macca.protocol_stack import EoMaccaStack
from eom_server.tcp_server import TCPServer
from eom_server.handlers import RequestHandler


@pytest.fixture(scope="session")
def stack() -> EoMaccaStack:
    """Provide a fresh EoMaccaStack instance."""
    return EoMaccaStack()


@pytest.fixture(scope="function")
def handler() -> RequestHandler:
    """Provide a fresh RequestHandler instance."""
    return RequestHandler()


@pytest.fixture(scope="session")
def test_payload() -> bytes:
    """Provide standard test payload."""
    return b"Test payload for EoMacca protocol"


@pytest.fixture(scope="function")
def test_file(tmp_path: Path) -> Path:
    """Create a temporary test file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("Test file content for EoMacca")
    return test_file


@pytest.fixture(scope="function")
def tcp_server(request: pytest.FixtureRequest) -> Generator[TCPServer, None, None]:
    """Start a TCP server in a thread for integration tests.

    Usage:
        @pytest.mark.parametrize("tcp_server", ["echo"], indirect=True)
        def test_with_server(tcp_server):
            # Server is running on tcp_server.port
            ...
    """
    mode = getattr(request, "param", "echo")

    server = TCPServer(host="127.0.0.1", port=0, mode=mode)  # type: ignore[arg-type]

    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()

    # Wait for server to be ready by polling for the assigned port
    max_retries = 50
    for _ in range(max_retries):
        if server.port != 0:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    s.connect(("127.0.0.1", server.port))
                break
            except (ConnectionRefusedError, socket.timeout):
                pass
        time.sleep(0.1)

    yield server

    server.running = False
    time.sleep(0.1)


@pytest.fixture(scope="session")
def sample_ethernet_frame() -> bytes:
    """Provide a sample Ethernet frame for testing."""

    frame = Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / Raw(
        load=b"Sample payload"
    )
    return bytes(frame)


@pytest.fixture(scope="function")
def temp_output_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for test outputs."""
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture(scope="session")
def encapsulator() -> Encapsulator:
    """Provide a single instance of the encapsulator for all tests."""
    return Encapsulator()


@pytest.fixture(scope="function")
def request_handler() -> RequestHandler:
    """Provide a fresh RequestHandler instance."""
    return RequestHandler()
