"""Tests for EoMacca HTTP server with live network I/O."""

from typing import Generator

import pytest
import requests

from eom_client.http_client import HTTPClient
from ethernet_over_macca.protocol_stack import EoMaccaStack
from eom_server.http_server import HTTPServer


@pytest.fixture
def live_http_server() -> Generator[HTTPServer, None, None]:
    """Start a live HTTP server on an OS-assigned port."""
    server = HTTPServer(mode="echo")
    server.run_in_thread(port=0, max_startup_secs=1.0)
    yield server

    server.stop()


class TestHTTPServerLive:
    """Integration tests using real HTTP over TCP."""

    def test_echo_round_trip(self, live_http_server: HTTPServer) -> None:
        """Test full encapsulation -> HTTP -> decapsulation round trip."""
        client = HTTPClient(base_url=f"http://127.0.0.1:{live_http_server.port}")
        message = "Hello through 8 layers via HTTP!"
        response = client.echo(message)
        assert response == message
        client.close()

    def test_ping_round_trip(self, live_http_server: HTTPServer) -> None:
        """Test ping mode through live HTTP."""
        live_http_server.mode = "ping"
        client = HTTPClient(base_url=f"http://127.0.0.1:{live_http_server.port}")
        rtts = client.ping(count=3)
        assert len(rtts) == 3
        assert all(rtt > 0 for rtt in rtts)
        client.close()

    def test_stats_endpoint(self, live_http_server: HTTPServer) -> None:
        """Test stats endpoint returns valid data."""
        url = f"http://127.0.0.1:{live_http_server.port}/stats"
        response = requests.get(url, timeout=5)
        assert response.status_code == 200
        data = response.json()
        assert "uptime_seconds" in data
        assert "packets_received" in data
        assert "packets_sent" in data

    def test_stats_increase_after_request(self, live_http_server: HTTPServer) -> None:
        """Test that stats counters increase after processing a request."""
        stats_url = f"http://127.0.0.1:{live_http_server.port}/stats"

        initial = requests.get(stats_url, timeout=5).json()

        client = HTTPClient(base_url=f"http://127.0.0.1:{live_http_server.port}")
        client.echo("stats test")
        client.close()

        final = requests.get(stats_url, timeout=5).json()
        assert final["packets_received"] > initial["packets_received"]
        assert final["packets_sent"] > initial["packets_sent"]

    def test_invalid_packet_returns_500(self, live_http_server: HTTPServer) -> None:
        """Test that malformed EoMacca packets return 500."""
        url = f"http://127.0.0.1:{live_http_server.port}/eomacca/v1/tunnel"
        response = requests.post(
            url,
            data=b"not a valid eomacca packet",
            headers={"Content-Type": "application/dns-message"},
            timeout=5,
        )
        assert response.status_code == 500

    def test_unexpected_content_type_still_processes(
        self, live_http_server: HTTPServer, stack: EoMaccaStack
    ) -> None:
        """Test that wrong content-type still processes the packet."""
        packet = stack.encapsulate(b"wrong content type test")

        url = f"http://127.0.0.1:{live_http_server.port}/eomacca/v1/tunnel"
        response = requests.post(
            url,
            data=packet,
            headers={"Content-Type": "text/plain"},
            timeout=5,
        )
        assert response.status_code == 200

        response_payload = live_http_server.stack.decapsulate(response.content)
        assert response_payload == b"wrong content type test"

    def test_overhead_is_realistic(self, live_http_server: HTTPServer) -> None:
        """Test that HTTP transport adds realistic overhead."""
        client = HTTPClient(base_url=f"http://127.0.0.1:{live_http_server.port}")

        small_msg = "X" * 10
        response = client.echo(small_msg)
        assert response == small_msg

        stats = client.get_stats()
        assert stats["packets_received"] > 0
        assert stats["total_overhead"] > 0
        client.close()


class TestHTTPClientUnit:
    """Unit tests for HTTPClient (no network)."""

    def test_client_initialization(self) -> None:
        """Test HTTPClient initialization."""
        client = HTTPClient(base_url="http://127.0.0.1:9999")
        assert client.base_url == "http://127.0.0.1:9999"
        assert client.stack is not None
        client.close()

    def test_client_initialization_with_trailing_slash(self) -> None:
        """Test HTTPClient strips trailing slash."""
        client = HTTPClient(base_url="http://127.0.0.1:9999/")
        assert client.base_url == "http://127.0.0.1:9999"
        client.close()

    def test_client_context_manager(self) -> None:
        """Test HTTPClient as context manager."""
        with HTTPClient(base_url="http://127.0.0.1:9999") as client:
            assert client.stack is not None
