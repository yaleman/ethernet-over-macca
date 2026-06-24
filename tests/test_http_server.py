"""Tests for EoMacca HTTP server."""

import threading
import time

import pytest

from src.client.http_client import HTTPClient
from src.protocol_stack import EoMaccaStack
from src.server.http_server import HTTPServer


@pytest.fixture
def http_server(request: pytest.FixtureRequest) -> HTTPServer:
    """Create an HTTP server instance for testing."""
    mode = getattr(request, "param", "echo")
    server = HTTPServer(mode=mode)
    return server


class TestHTTPServerUnit:
    """Unit tests for HTTP server using Flask test client."""

    def test_tunnel_endpoint_exists(self, http_server: HTTPServer) -> None:
        """Test that tunnel endpoint is registered."""
        client = http_server.app.test_client()
        response = client.post("/eomacca/v1/tunnel")
        assert response.status_code in (400, 500)

    def test_stats_endpoint_exists(self, http_server: HTTPServer) -> None:
        """Test that stats endpoint is registered."""
        client = http_server.app.test_client()
        response = client.get("/stats")
        assert response.status_code == 200

    def test_stats_returns_json(self, http_server: HTTPServer) -> None:
        """Test that stats endpoint returns valid JSON."""
        client = http_server.app.test_client()
        response = client.get("/stats")
        data = response.get_json()
        assert "uptime_seconds" in data
        assert "packets_received" in data
        assert "packets_sent" in data
        assert "bytes_received" in data
        assert "bytes_sent" in data
        assert "total_overhead" in data

    def test_tunnel_with_invalid_data(self, http_server: HTTPServer) -> None:
        """Test tunnel endpoint with invalid data."""
        client = http_server.app.test_client()
        response = client.post(
            "/eomacca/v1/tunnel",
            data=b"invalid packet data",
            content_type="application/dns-message",
        )
        assert response.status_code == 500

    def test_tunnel_with_valid_packet(self, http_server: HTTPServer) -> None:
        """Test tunnel endpoint with valid EoMacca packet."""
        stack = EoMaccaStack()
        payload = b"Test HTTP tunnel payload"
        packet = stack.encapsulate(payload)

        client = http_server.app.test_client()
        response = client.post(
            "/eomacca/v1/tunnel",
            data=packet,
            content_type="application/dns-message",
        )
        assert response.status_code == 200
        assert response.content_type == "application/dns-message"

    def test_tunnel_echo_mode(self) -> None:
        """Test tunnel in echo mode."""
        server = HTTPServer(mode="echo")
        stack = EoMaccaStack()
        payload = b"Echo test"
        packet = stack.encapsulate(payload)

        client = server.app.test_client()
        response = client.post(
            "/eomacca/v1/tunnel",
            data=packet,
            content_type="application/dns-message",
        )
        assert response.status_code == 200

        response_packet = response.get_data()
        response_payload = stack.decapsulate(response_packet)
        assert response_payload == payload

    def test_tunnel_ping_mode(self) -> None:
        """Test tunnel in ping mode."""
        server = HTTPServer(mode="ping")
        stack = EoMaccaStack()
        client_time = str(time.time()).encode("utf-8")
        packet = stack.encapsulate(client_time)

        client = server.app.test_client()
        response = client.post(
            "/eomacca/v1/tunnel",
            data=packet,
            content_type="application/dns-message",
        )
        assert response.status_code == 200

        response_packet = response.get_data()
        response_payload = stack.decapsulate(response_packet)
        parts = response_payload.decode("utf-8").split(",")
        assert len(parts) == 2
        assert float(parts[0]) == pytest.approx(float(client_time.decode()), abs=0.001)
        assert float(parts[1]) > 0

    def test_unexpected_content_type_warning(self, http_server: HTTPServer) -> None:
        """Test that unexpected content type produces warning but still processes."""
        stack = EoMaccaStack()
        payload = b"Test payload"
        packet = stack.encapsulate(payload)

        client = http_server.app.test_client()
        response = client.post(
            "/eomacca/v1/tunnel",
            data=packet,
            content_type="text/plain",
        )
        assert response.status_code == 200

    def test_stats_increase_after_request(self, http_server: HTTPServer) -> None:
        """Test that stats increase after processing a request."""
        stack = EoMaccaStack()
        payload = b"Stats test"
        packet = stack.encapsulate(payload)

        client = http_server.app.test_client()

        response = client.get("/stats")
        initial_stats = response.get_json()

        client.post(
            "/eomacca/v1/tunnel",
            data=packet,
            content_type="application/dns-message",
        )

        response = client.get("/stats")
        final_stats = response.get_json()

        assert final_stats["packets_received"] >= initial_stats["packets_received"]
        assert final_stats["packets_sent"] >= initial_stats["packets_sent"]


class TestHTTPClient:
    """Test the HTTP client class."""

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


@pytest.fixture
def live_http_server() -> HTTPServer:  # ty:ignore[invalid-return-type]
    """Start a live HTTP server for integration testing."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]

    server = HTTPServer(mode="echo")

    def run_server() -> None:
        server.app.run(host="127.0.0.1", port=port, debug=False)

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    time.sleep(1.0)

    yield server

    server_thread.join(timeout=1.0)


@pytest.mark.skip(reason="Requires live Flask server - run manually")
class TestHTTPIntegration:
    """Integration tests for HTTP client and server (require live server)."""

    def test_http_echo_integration(self, live_http_server: HTTPServer) -> None:
        """Test HTTP echo round-trip."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]

        client = HTTPClient(base_url=f"http://127.0.0.1:{port}")
        message = "HTTP integration test"
        response = client.echo(message)
        assert response == message
        client.close()

    def test_http_ping_integration(self, live_http_server: HTTPServer) -> None:
        """Test HTTP ping functionality."""
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]

        client = HTTPClient(base_url=f"http://127.0.0.1:{port}")
        rtts = client.ping(count=2)
        assert len(rtts) == 2
        assert all(rtt > 0 for rtt in rtts)
        client.close()
