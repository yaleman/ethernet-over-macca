"""Request handlers for EoMacca server."""

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from rich.console import Console

console = Console()


@dataclass
class Statistics:
    """Track server statistics."""

    packets_received: int = 0
    packets_sent: int = 0
    bytes_received: int = 0
    bytes_sent: int = 0
    total_overhead: int = 0
    start_time: float = field(default_factory=time.time)

    def update_received(self, packet_size: int, payload_size: int) -> None:
        """Update statistics for received packet."""
        self.packets_received += 1
        self.bytes_received += packet_size
        self.total_overhead += packet_size - payload_size

    def update_sent(self, packet_size: int) -> None:
        """Update statistics for sent packet."""
        self.packets_sent += 1
        self.bytes_sent += packet_size

    def get_uptime(self) -> float:
        """Get server uptime in seconds."""
        return time.time() - self.start_time

    def display(self) -> None:
        """Display statistics."""
        uptime = self.get_uptime()
        console.print("\n[bold cyan]Server Statistics[/bold cyan]")
        console.print(f"  Uptime: {uptime:.2f}s")
        console.print(f"  Packets RX: {self.packets_received}")
        console.print(f"  Packets TX: {self.packets_sent}")
        console.print(f"  Bytes RX: {self.bytes_received:,}")
        console.print(f"  Bytes TX: {self.bytes_sent:,}")
        console.print(f"  Overhead: {self.total_overhead:,} bytes")
        if self.packets_received > 0:
            avg_overhead = self.total_overhead / self.packets_received
            console.print(f"  Avg overhead: {avg_overhead:.1f} bytes/packet")


class RequestHandler:
    """Handle different types of EoMacca requests."""

    def __init__(self) -> None:
        """Initialize request handler."""
        self.stats = Statistics()
        self.chat_history: list[tuple[str, str]] = []  # (timestamp, message)
        self.files: dict[str, bytes] = {}

    def handle_echo(self, payload: bytes) -> bytes:
        """Echo back the payload."""
        console.print(f"[green]ECHO:[/green] Received {len(payload)} bytes")
        return payload

    def handle_chat(self, payload: bytes) -> bytes:
        """Handle chat message."""
        try:
            message = payload.decode("utf-8")
            timestamp = time.strftime("%H:%M:%S")
            self.chat_history.append((timestamp, message))

            console.print(f"[yellow]CHAT [{timestamp}]:[/yellow] {message}")

            # Send acknowledgment
            ack = f"Message received at {timestamp}".encode("utf-8")
            return ack
        except UnicodeDecodeError:
            return b"Error: Invalid UTF-8"

    def handle_file(self, payload: bytes) -> bytes:
        """Handle file transfer."""
        # File format: filename_length (4 bytes) + filename + file_data
        if len(payload) < 4:
            return b"Error: Invalid file format"

        filename_length = int.from_bytes(payload[:4], "big")
        if len(payload) < 4 + filename_length:
            return b"Error: Incomplete file data"

        filename = payload[4 : 4 + filename_length].decode("utf-8")
        file_data = payload[4 + filename_length :]

        self.files[filename] = file_data

        console.print(
            f"[magenta]FILE:[/magenta] Received '{filename}' ({len(file_data)} bytes)"
        )
        console.print(
            f"  [dim]Total overhead: {len(payload) - len(file_data)} bytes[/dim]"
        )

        return f"File '{filename}' received ({len(file_data)} bytes)".encode("utf-8")

    def handle_ping(self, payload: bytes) -> bytes:
        """Handle ping request."""
        # Payload should contain timestamp from client
        try:
            client_time = float(payload.decode("utf-8"))
            server_time = time.time()

            console.print("[blue]PING:[/blue] RTT will be calculated by client")

            # Send back both timestamps
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
        if filename not in self.files:
            return False

        output_path = output_dir / filename
        output_path.write_bytes(self.files[filename])
        console.print(f"[green]Saved file to {output_path}[/green]")
        return True
