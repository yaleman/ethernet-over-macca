"""TCP client for EoMacca protocol."""

import socket
import struct
import time
from pathlib import Path

from ethernet_over_macca import get_logger, MAX_FILENAME_LENGTH
from ethernet_over_macca.protocol_stack import EoMaccaStack
from .ui import UI

CONSOLE = get_logger()

MAX_PACKET_SIZE = 102 * 1024 * 1024  # 102MB max packet size


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket, raising on disconnect."""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(
                f"Connection closed while receiving data from server: laddr={sock.getsockname()} raddr={sock.getpeername()}"
            )
        data.extend(chunk)
    return bytes(data)


def recv_packet(sock: socket.socket) -> bytes:
    """Receive a length-prefixed packet."""
    length_bytes = recv_exact(sock, 4)
    length = struct.unpack(">I", length_bytes)[0]
    if length > MAX_PACKET_SIZE:
        raise ValueError(f"Packet too large: {length} bytes (max {MAX_PACKET_SIZE})")
    return recv_exact(sock, length)


def send_packet(sock: socket.socket, data: bytes) -> None:
    """Send a length-prefixed packet."""
    length_prefix = struct.pack(">I", len(data))
    sock.sendall(length_prefix + data)


class TCPClient:
    """TCP client for sending EoMacca packets."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9999) -> None:
        """Initialize TCP client.

        Args:
            host: Server host
            port: Server port
        """
        self.host = host
        self.port = port
        self.stack = EoMaccaStack()
        self.ui = UI()

    def send_receive(
        self, payload: bytes, show_visualization: bool = True
    ) -> tuple[bytes, float]:
        """Send payload and receive response.

        Args:
            payload: Payload to send
            show_visualization: Whether to show packet visualization

        Returns:
            Tuple of (response_payload, latency_ms)
        """
        # Encapsulate
        packet = self.stack.encapsulate(payload)

        if show_visualization:
            CONSOLE.print("\n[cyan]Encapsulating payload...[/cyan]")
            CONSOLE.print(f"  Payload size: {len(payload)} bytes")
            CONSOLE.print(f"  Packet size: {len(packet)} bytes")
            CONSOLE.print(
                f"  Overhead: {len(packet) - len(payload)} bytes "
                f"({(len(packet) - len(payload)) / max(len(payload), 1) * 100:.1f}%)"
            )

        # Send and receive
        start_time = time.perf_counter()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))

            if show_visualization:
                CONSOLE.print(f"\n[green]Connected to {self.host}:{self.port}[/green]")
                CONSOLE.print(f"[cyan]Sending {len(packet)} bytes...[/cyan]")

            send_packet(s, packet)

            # Receive response
            response_packet = recv_packet(s)

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        if show_visualization:
            CONSOLE.print(f"[cyan]Received {len(response_packet)} bytes[/cyan]")

        # Decapsulate response
        response_payload = self.stack.decapsulate(response_packet)

        if show_visualization:
            CONSOLE.print(
                f"[green]Decapsulated response: {len(response_payload)} bytes[/green]"
            )
            CONSOLE.print(f"[yellow]Round-trip time: {latency_ms:.2f}ms[/yellow]\n")

        return response_payload, latency_ms

    def echo(self, message: str) -> str:
        """Send echo request.

        Args:
            message: Message to echo

        Returns:
            Echoed message
        """
        payload = message.encode("utf-8")
        response, latency = self.send_receive(payload)
        return response.decode("utf-8")

    def chat(self, message: str) -> str:
        """Send chat message.

        Args:
            message: Chat message

        Returns:
            Server acknowledgment
        """
        payload = message.encode("utf-8")
        response, latency = self.send_receive(payload, show_visualization=False)

        CONSOLE.print(f"[green]→[/green] {message}")
        CONSOLE.print(
            f"[blue]←[/blue] {response.decode('utf-8')} [dim]({latency:.1f}ms)[/dim]"
        )

        return response.decode("utf-8")

    def send_file(self, file_path: Path) -> str:
        """Send file to server.

        Args:
            file_path: Path to file to send

        Returns:
            Server response
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        filename = file_path.name
        file_data = file_path.read_bytes()

        # Format: filename_length (4 bytes) + filename + file_data
        filename_bytes = filename.encode("utf-8")
        filename_length = len(filename_bytes).to_bytes(4, "big")
        if len(filename_bytes) > MAX_FILENAME_LENGTH:
            raise ValueError(f"Filename too long (max {MAX_FILENAME_LENGTH} bytes)")

        payload = filename_length + filename_bytes + file_data

        CONSOLE.print(f"\n[cyan]Sending file: {filename}[/cyan]")
        CONSOLE.print(f"  File size: {len(file_data)} bytes")

        response, latency = self.send_receive(payload)

        CONSOLE.print(f"[green]Server response:[/green] {response.decode('utf-8')}")
        CONSOLE.print(f"[yellow]Transfer time: {latency:.2f}ms[/yellow]")

        return response.decode("utf-8")

    def ping(self, count: int = 5) -> list[float]:
        """Send ping requests to measure latency.

        Args:
            count: Number of pings to send

        Returns:
            List of RTT measurements in milliseconds
        """
        rtts: list[float] = []

        CONSOLE.print(
            f"\n[cyan]Pinging {self.host}:{self.port} ({count} times)...[/cyan]\n"
        )

        for i in range(count):
            # Send current timestamp
            client_time = str(time.time()).encode("utf-8")
            response, _ = self.send_receive(client_time, show_visualization=False)

            # Parse response (contains client_time, server_time)
            try:
                parts = response.decode("utf-8").split(",")
                sent_time = float(parts[0])
                received_time = time.time()

                rtt = (received_time - sent_time) * 1000  # Convert to ms
                rtts.append(rtt)

                CONSOLE.print(f"[green]Ping {i + 1}:[/green] RTT = {rtt:.2f}ms")

            except (ValueError, IndexError) as e:
                CONSOLE.print(f"[red]Error parsing ping response: {e}[/red]")

            if i < count - 1:
                time.sleep(0.5)  # Small delay between pings

        # Statistics
        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
            min_rtt = min(rtts)
            max_rtt = max(rtts)

            CONSOLE.print("\n[bold]Ping Statistics:[/bold]")
            CONSOLE.print(f"  Packets: {count}")
            CONSOLE.print(f"  Min RTT: {min_rtt:.2f}ms")
            CONSOLE.print(f"  Avg RTT: {avg_rtt:.2f}ms")
            CONSOLE.print(f"  Max RTT: {max_rtt:.2f}ms")

        return rtts
