"""Tests for EoMacca client components."""

from unittest.mock import MagicMock, patch


from src.client.ui import UI


class TestUI:
    """Test the UI utility class."""

    def test_print_header(self) -> None:
        """Test header printing."""
        # Just verify it doesn't crash
        UI.print_header("Test Header")

    def test_print_packet_visualization(self) -> None:
        """Test packet visualization."""
        layers = [
            ("Outer Ethernet", 456),
            ("Outer IP", 442),
            ("Outer TCP", 402),
        ]
        # Verify it doesn't crash
        UI.print_packet_visualization(
            payload_size=14, encapsulated_size=456, layers=layers
        )

    def test_print_stats(self) -> None:
        """Test statistics printing."""
        stats = {
            "packets": 10,
            "bytes": 5000,
            "efficiency": 15.5,
        }
        # Verify it doesn't crash
        UI.print_stats(stats)

    def test_print_success(self) -> None:
        """Test success message."""
        UI.print_success("Operation completed")

    def test_print_error(self) -> None:
        """Test error message."""
        UI.print_error("Operation failed")

    def test_print_info(self) -> None:
        """Test info message."""
        UI.print_info("Information message")

    def test_print_warning(self) -> None:
        """Test warning message."""
        UI.print_warning("Warning message")

    def test_show_progress(self) -> None:
        """Test progress spinner creation."""
        progress = UI.show_progress("Processing...")
        assert progress is not None
        progress.stop()

    def test_print_panel(self) -> None:
        """Test panel printing."""
        UI.print_panel("Panel content", "Panel Title")

    def test_measure_latency(self) -> None:
        """Test latency measurement utility."""

        def test_function() -> str:
            return "result"

        result, latency = UI.measure_latency(test_function)
        assert result == "result"
        assert latency >= 0
        assert latency < 1000  # Should be very fast


class TestTCPClientMethods:
    """Test TCPClient methods (without actual network)."""

    @patch("socket.socket")
    def test_send_receive_mock(self, mock_socket: MagicMock) -> None:
        """Test send_receive with mocked socket."""
        from src.client.tcp_client import TCPClient
        from src.protocol_stack import EoMaccaStack

        # Setup mock socket
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance

        # Create a fake response packet
        stack = EoMaccaStack()
        response_payload = b"Echo response"
        response_packet = stack.encapsulate(response_payload)
        mock_sock_instance.recv.return_value = response_packet

        # Test client
        client = TCPClient()
        result, latency = client.send_receive(b"Test", show_visualization=False)

        assert result == response_payload
        assert latency >= 0
        mock_sock_instance.connect.assert_called_once_with(("127.0.0.1", 9999))
        mock_sock_instance.sendall.assert_called_once()

    def test_client_initialization(self) -> None:
        """Test TCPClient initialization."""
        from src.client.tcp_client import TCPClient

        client = TCPClient(host="localhost", port=8888)
        assert client.host == "localhost"
        assert client.port == 8888
        assert client.stack is not None
        assert client.ui is not None
