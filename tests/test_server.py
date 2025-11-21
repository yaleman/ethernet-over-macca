"""Tests for EoMacca server components."""

import time
from pathlib import Path


from src.server.handlers import RequestHandler, Statistics


class TestStatistics:
    """Test the Statistics tracking class."""

    def test_initialization(self) -> None:
        """Test Statistics initialization."""
        stats = Statistics()
        assert stats.packets_received == 0
        assert stats.packets_sent == 0
        assert stats.bytes_received == 0
        assert stats.bytes_sent == 0
        assert stats.total_overhead == 0
        assert stats.start_time > 0

    def test_update_received(self) -> None:
        """Test updating received packet statistics."""
        stats = Statistics()
        stats.update_received(packet_size=500, payload_size=50)

        assert stats.packets_received == 1
        assert stats.bytes_received == 500
        assert stats.total_overhead == 450

    def test_update_sent(self) -> None:
        """Test updating sent packet statistics."""
        stats = Statistics()
        stats.update_sent(packet_size=500)

        assert stats.packets_sent == 1
        assert stats.bytes_sent == 500

    def test_multiple_packets(self) -> None:
        """Test statistics with multiple packets."""
        stats = Statistics()

        stats.update_received(500, 50)
        stats.update_received(600, 60)
        stats.update_sent(500)
        stats.update_sent(600)

        assert stats.packets_received == 2
        assert stats.packets_sent == 2
        assert stats.bytes_received == 1100
        assert stats.bytes_sent == 1100
        assert stats.total_overhead == 990  # (500-50) + (600-60)

    def test_get_uptime(self) -> None:
        """Test uptime calculation."""
        stats = Statistics()
        time.sleep(0.1)
        uptime = stats.get_uptime()
        assert uptime >= 0.1
        assert uptime < 1.0


class TestRequestHandler:
    """Test the RequestHandler class."""

    def test_initialization(self, handler: RequestHandler) -> None:
        """Test RequestHandler initialization."""
        assert isinstance(handler.stats, Statistics)
        assert handler.chat_history == []
        assert handler.files == {}

    def test_handle_echo(self, handler: RequestHandler) -> None:
        """Test echo handler."""
        payload = b"Test message"
        response = handler.handle_echo(payload)
        assert response == payload

    def test_handle_chat(self, handler: RequestHandler) -> None:
        """Test chat message handler."""
        message = "Hello, EoMacca!"
        payload = message.encode("utf-8")

        response = handler.handle_chat(payload)

        assert b"Message received at" in response
        assert len(handler.chat_history) == 1
        timestamp, msg = handler.chat_history[0]
        assert msg == message
        assert len(timestamp) > 0  # HH:MM:SS format

    def test_handle_chat_invalid_utf8(self, handler: RequestHandler) -> None:
        """Test chat with invalid UTF-8."""
        payload = b"\xff\xfe"  # Invalid UTF-8
        response = handler.handle_chat(payload)
        assert response == b"Error: Invalid UTF-8"

    def test_handle_file(self, handler: RequestHandler) -> None:
        """Test file upload handler."""
        filename = "test.txt"
        file_data = b"Test file content"

        # Format: filename_length (4 bytes) + filename + file_data
        filename_bytes = filename.encode("utf-8")
        filename_length = len(filename_bytes).to_bytes(4, "big")
        payload = filename_length + filename_bytes + file_data

        response = handler.handle_file(payload)

        assert filename in handler.files
        assert handler.files[filename] == file_data
        assert b"received" in response.lower()
        assert str(len(file_data)).encode() in response

    def test_handle_file_invalid_format(self, handler: RequestHandler) -> None:
        """Test file handler with invalid data."""
        payload = b"abc"  # Too short
        response = handler.handle_file(payload)
        assert b"Error" in response

    def test_handle_file_incomplete_data(self, handler: RequestHandler) -> None:
        """Test file handler with incomplete data."""
        filename_length = (100).to_bytes(4, "big")  # Claims 100 byte filename
        payload = filename_length + b"short"  # But only provides a few bytes
        response = handler.handle_file(payload)
        assert b"Error" in response

    def test_handle_ping(self, handler: RequestHandler) -> None:
        """Test ping handler."""
        client_time = str(time.time()).encode("utf-8")
        response = handler.handle_ping(client_time)

        # Response should contain client_time,server_time
        parts = response.decode("utf-8").split(",")
        assert len(parts) == 2
        assert float(parts[0]) > 0  # Client timestamp
        assert float(parts[1]) > 0  # Server timestamp

    def test_handle_ping_invalid(self, handler: RequestHandler) -> None:
        """Test ping with invalid data."""
        payload = b"not a timestamp"
        response = handler.handle_ping(payload)
        assert b"Error" in response

    def test_handle_request_routing(self, handler: RequestHandler) -> None:
        """Test request routing to correct handler."""
        payload = b"Test"

        # Test each mode
        echo_response = handler.handle_request(payload, "echo")
        assert echo_response == payload

        chat_response = handler.handle_request(payload, "chat")
        assert b"Message received" in chat_response

        # Ping requires specific format
        ping_payload = str(time.time()).encode()
        ping_response = handler.handle_request(ping_payload, "ping")
        assert b"," in ping_response

    def test_save_file(self, handler: RequestHandler, temp_output_dir: Path) -> None:
        """Test saving received file to disk."""
        filename = "saved_test.txt"
        file_data = b"File content"
        handler.files[filename] = file_data

        success = handler.save_file(filename, temp_output_dir)

        assert success
        saved_file = temp_output_dir / filename
        assert saved_file.exists()
        assert saved_file.read_bytes() == file_data

    def test_save_nonexistent_file(
        self, handler: RequestHandler, temp_output_dir: Path
    ) -> None:
        """Test saving a file that doesn't exist."""
        success = handler.save_file("nonexistent.txt", temp_output_dir)
        assert not success
