"""Tests for discovered bugs in EoMacca."""

import struct
from unittest.mock import MagicMock, patch

import pytest

from eom_client.http_client import HTTPClient
from eom_client.tcp_client import TCPClient
from eom_server.handlers import RequestHandler
from ethernet_over_macca.protocol_stack import EoMaccaStack


class TestHTTPClientErrorHandling:
    """Test that HTTP client properly handles 500 error responses."""

    def test_http_client_decapsulates_500_error_response(
        self, stack: EoMaccaStack
    ) -> None:
        """HTTP server returns 500 with encapsulated error — client should not raise HTTPError.

        The server at http_server.py:114 returns status=500 with an encapsulated
        error message. The client should decapsulate and return the inner error,
        not raise requests.HTTPError.
        """
        client = HTTPClient(base_url="http://127.0.0.1:8080")

        error_payload = b"Error: No outer IP layer found"
        error_packet = stack.encapsulate(error_payload)

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.content = error_packet
        mock_response.text = error_packet.decode("latin-1")

        with patch.object(client.session, "post", return_value=mock_response):
            with pytest.raises(RuntimeError, match="No outer IP layer found"):
                client.send_receive(b"test", show_visualization=False)

        client.close()

    def test_http_client_normal_response_still_works(self, stack: EoMaccaStack) -> None:
        """Verify normal 200 responses still work correctly."""
        client = HTTPClient(base_url="http://127.0.0.1:8080")

        payload = b"Normal response"
        response_packet = stack.encapsulate(payload)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = response_packet

        with patch.object(client.session, "post", return_value=mock_response):
            result, latency = client.send_receive(payload, show_visualization=False)
            assert result == payload

        client.close()


class TestTCPClientZeroDivision:
    """Test that TCP client handles empty payload without ZeroDivisionError."""

    def test_empty_payload_does_not_crash_visualization(
        self, stack: EoMaccaStack
    ) -> None:
        """Sending empty payload should not cause ZeroDivisionError in visualization.

        Bug: tcp_client.py:51 divides by len(payload) without guarding for zero.
        """
        client = TCPClient(host="127.0.0.1", port=9999)

        empty_packet = stack.encapsulate(b"")

        mock_sock = MagicMock()

        # First recv returns 4 bytes (length prefix), second returns the actual data
        length_prefix = struct.pack(">I", len(empty_packet))
        mock_sock.recv.side_effect = [length_prefix[i : i + 1] for i in range(4)] + [
            empty_packet
        ]

        with patch("socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

            try:
                result, latency = client.send_receive(b"", show_visualization=True)
                assert result == b""
            except ZeroDivisionError:
                pytest.fail("ZeroDivisionError when sending empty payload")

    def test_empty_payload_send_receive_no_viz(self, stack: EoMaccaStack) -> None:
        """Empty payload without visualization should work."""
        client = TCPClient(host="127.0.0.1", port=9999)

        empty_packet = stack.encapsulate(b"")

        mock_sock = MagicMock()

        length_prefix = struct.pack(">I", len(empty_packet))
        mock_sock.recv.side_effect = [length_prefix[i : i + 1] for i in range(4)] + [
            empty_packet
        ]

        with patch("socket.socket") as mock_socket_cls:
            mock_socket_cls.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_socket_cls.return_value.__exit__ = MagicMock(return_value=False)

            result, latency = client.send_receive(b"", show_visualization=False)
            assert result == b""


class TestFilenameLengthValidation:
    """Test that filename length is validated to prevent DoS."""

    def test_filename_too_long_rejected(self, request_handler: RequestHandler) -> None:
        """A filename length > 4096 should be rejected."""

        payload = struct.pack(">I", 5000) + b"x" * 100
        response = request_handler.handle_file(payload)

        assert b"Filename too long" in response

    def test_filename_length_reasonable_accepted(
        self, request_handler: RequestHandler
    ) -> None:
        """A reasonable filename length should be processed."""

        filename = b"test.txt"
        filename_length = len(filename).to_bytes(4, "big")
        payload = filename_length + filename + b"file content"
        response = request_handler.handle_file(payload)

        assert b"received" in response
        assert b"test.txt" in response
