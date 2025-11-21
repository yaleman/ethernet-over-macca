"""TCP client for EoMacca protocol."""

import socket
import time
from pathlib import Path

from rich.console import Console

from ..protocol_stack import EoMaccaStack
from .ui import UI

console = Console()


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
            console.print("\n[cyan]Encapsulating payload...[/cyan]")
            console.print(f"  Payload size: {len(payload)} bytes")
            console.print(f"  Packet size: {len(packet)} bytes")
            console.print(
                f"  Overhead: {len(packet) - len(payload)} bytes "
                f"({(len(packet) - len(payload)) / len(payload) * 100:.1f}%)"
            )

        # Send and receive
        start_time = time.perf_counter()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))

            if show_visualization:
                console.print(f"\n[green]Connected to {self.host}:{self.port}[/green]")
                console.print(f"[cyan]Sending {len(packet)} bytes...[/cyan]")

            s.sendall(packet)

            # Receive response
            response_packet = s.recv(65536)

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        if show_visualization:
            console.print(f"[cyan]Received {len(response_packet)} bytes[/cyan]")

        # Decapsulate response
        response_payload = self.stack.decapsulate(response_packet)

        if show_visualization:
            console.print(
                f"[green]Decapsulated response: {len(response_payload)} bytes[/green]"
            )
            console.print(f"[yellow]Round-trip time: {latency_ms:.2f}ms[/yellow]\n")

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

        console.print(f"[green]→[/green] {message}")
        console.print(
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

        payload = filename_length + filename_bytes + file_data

        console.print(f"\n[cyan]Sending file: {filename}[/cyan]")
        console.print(f"  File size: {len(file_data)} bytes")

        response, latency = self.send_receive(payload)

        console.print(f"[green]Server response:[/green] {response.decode('utf-8')}")
        console.print(f"[yellow]Transfer time: {latency:.2f}ms[/yellow]")

        return response.decode("utf-8")

    def ping(self, count: int = 5) -> list[float]:
        """Send ping requests to measure latency.

        Args:
            count: Number of pings to send

        Returns:
            List of RTT measurements in milliseconds
        """
        rtts: list[float] = []

        console.print(
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

                console.print(f"[green]Ping {i + 1}:[/green] RTT = {rtt:.2f}ms")

            except (ValueError, IndexError) as e:
                console.print(f"[red]Error parsing ping response: {e}[/red]")

            if i < count - 1:
                time.sleep(0.5)  # Small delay between pings

        # Statistics
        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
            min_rtt = min(rtts)
            max_rtt = max(rtts)

            console.print("\n[bold]Ping Statistics:[/bold]")
            console.print(f"  Packets: {count}")
            console.print(f"  Min RTT: {min_rtt:.2f}ms")
            console.print(f"  Avg RTT: {avg_rtt:.2f}ms")
            console.print(f"  Max RTT: {max_rtt:.2f}ms")

        return rtts
