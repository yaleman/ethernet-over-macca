"""Request handlers for EoMacca server."""

import sys

from ethernet_over_macca import get_logger, MAX_FILENAME_LENGTH

import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


CONSOLE = get_logger()


@dataclass
class Statistics:
    """Track server statistics."""

    packets_received: int = 0
    packets_sent: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    rx_overhead: int = 0
    tx_overhead: int = 0

    start_time: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def total_overhead(self) -> int:
        """Calculate total overhead in bytes."""
        return self.rx_overhead + self.tx_overhead

    def update_received(self, packet_size: int, payload_size: int) -> None:
        """Update statistics for received packet."""
        with self._lock:
            self.packets_received += 1
            self.bytes_received += packet_size
            self.rx_overhead += packet_size - payload_size

    def update_sent(self, packet_size: int, payload_size: int) -> None:
        """Update statistics for sent packet."""
        with self._lock:
            self.packets_sent += 1
            self.bytes_sent += packet_size
            self.tx_overhead += packet_size - payload_size

    def get_uptime(self) -> float:
        """Get server uptime in seconds."""
        return time.time() - self.start_time

    def display(self) -> None:
        """Display statistics."""
        with self._lock:
            uptime = self.get_uptime()
            try:
                CONSOLE.print("\n[bold cyan]Server Statistics[/bold cyan]")
                CONSOLE.print(f"  Uptime: {uptime:.2f}s")
                if self.packets_received > 0:
                    CONSOLE.print(f"  Packets RX: {self.packets_received}")
                    CONSOLE.print(f"  Packets TX: {self.packets_sent}")
                    CONSOLE.print(
                        f"  Bytes RX: {self.bytes_received:,} (overhead: {self.rx_overhead:,})"
                    )
                    CONSOLE.print(
                        f"  Bytes TX: {self.bytes_sent:,} (overhead: {self.tx_overhead:,})"
                    )
                    total_transferred = self.bytes_received + self.bytes_sent
                    payload_transferred = total_transferred - self.total_overhead
                    avg_over = self.total_overhead / self.packets_received
                    CONSOLE.print(f"  Total transferred: {total_transferred:,} bytes")
                    CONSOLE.print(f"  Payload data:      {payload_transferred:,} bytes")
                    CONSOLE.print(f"  Overhead:          {self.total_overhead:,} bytes")
                    CONSOLE.print(f"  Avg overhead:      {avg_over:.1f} bytes/packet")
                else:
                    CONSOLE.print("  No packets received yet.")
            except Exception as e:
                if "pytest" in sys.modules:
                    # because it's shutting down, we don't want to raise an exception in pytest because the logger has been closed
                    return
                raise e


class RequestHandler:
    """Handle different types of EoMacca requests."""

    def __init__(self) -> None:
        """Initialize request handler."""
        self.stats = Statistics()
        self._chat_lock = threading.Lock()
        self._files_lock = threading.Lock()
        self.chat_history: list[tuple[str, str]] = []
        self.files: dict[str, bytes] = {}

    def handle_echo(self, payload: bytes) -> bytes:
        """Echo back the payload."""
        CONSOLE.print(f"[green]ECHO:[/green] Received {len(payload)} bytes")
        return payload

    def handle_chat(self, payload: bytes) -> bytes:
        """Handle chat message."""
        try:
            message = payload.decode("utf-8")
            timestamp = time.strftime("%H:%M:%S")

            with self._chat_lock:
                self.chat_history.append((timestamp, message))

            CONSOLE.print(f"[yellow]CHAT [{timestamp}]:[/yellow] {message}")

            ack = f"Message received at {timestamp}".encode("utf-8")
            return ack
        except UnicodeDecodeError:
            return b"Error: Invalid UTF-8"

    def handle_file(self, payload: bytes) -> bytes:
        """Handle file transfer."""
        if len(payload) < 4:
            return b"Error: Invalid file format"

        filename_length = int.from_bytes(payload[:4], "big")
        if filename_length > MAX_FILENAME_LENGTH:
            return b"Error: Filename too long"
        if len(payload) < 4 + filename_length:
            return b"Error: Incomplete file data"

        filename = payload[4 : 4 + filename_length].decode("utf-8")
        file_data = payload[4 + filename_length :]

        with self._files_lock:
            self.files[filename] = file_data

        CONSOLE.print(
            f"[magenta]FILE:[/magenta] Received '{filename}' ({len(file_data)} bytes)"
        )
        CONSOLE.print(
            f"  [dim]Total overhead: {len(payload) - len(file_data)} bytes[/dim]"
        )

        return f"File '{filename}' received ({len(file_data)} bytes)".encode("utf-8")

    def handle_ping(self, payload: bytes) -> bytes:
        """Handle ping request."""
        try:
            client_time = float(payload.decode("utf-8"))
            server_time = time.time()

            CONSOLE.print("[yellow]PING! Sending PONG![/yellow]")

            response = f"{client_time},{server_time}".encode("utf-8")
            return response
        except (ValueError, UnicodeDecodeError):
            return b"Error: Invalid ping format"

    def handle_request(
        self, payload: bytes, request_type: Literal["echo", "chat", "file", "ping"]
    ) -> bytes:
        """Route request to appropriate handler."""
        handlers = {
            "echo": self.handle_echo,
            "chat": self.handle_chat,
            "file": self.handle_file,
            "ping": self.handle_ping,
        }

        handler = handlers.get(request_type, self.handle_echo)
        return handler(payload)

    def save_file(self, filename: str, output_dir: Path) -> bool:
        """Save received file to disk."""
        with self._files_lock:
            if filename not in self.files:
                return False
            file_data = self.files[filename]

        output_path = output_dir / filename
        output_path.write_bytes(file_data)
        CONSOLE.print(f"[green]Saved file to {output_path}[/green]")
        return True
