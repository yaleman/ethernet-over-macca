"""HTTP client for EoMacca protocol."""

import time
from typing import Optional

import requests
from rich.console import Console

from ..protocol_stack import EoMaccaStack

console = Console()


class HTTPClient:
    """HTTP client for sending EoMacca packets via the HTTP tunnel."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8080",
        timeout: float = 30.0,
    ) -> None:
        """Initialize HTTP client.

        Args:
            base_url: Base URL of the EoMacca HTTP server
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.stack = EoMaccaStack()
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/dns-message"}
        )

    def send_receive(
        self, payload: bytes, show_visualization: bool = True
    ) -> tuple[bytes, float]:
        """Send payload through HTTP tunnel and receive response.

        Args:
            payload: Payload to send
            show_visualization: Whether to show packet visualization

        Returns:
            Tuple of (response_payload, latency_ms)
        """
        packet = self.stack.encapsulate(payload)

        if show_visualization:
            console.print("\n[cyan]Encapsulating payload...[/cyan]")
            console.print(f"  Payload size: {len(payload)} bytes")
            console.print(f"  Packet size: {len(packet)} bytes")
            console.print(
                f"  Overhead: {len(packet) - len(payload)} bytes "
                f"({(len(packet) - len(payload)) / max(len(payload), 1) * 100:.1f}%)"
            )

        url = f"{self.base_url}/eomacca/v1/tunnel"
        start_time = time.perf_counter()

        response = self.session.post(
            url,
            data=packet,
            timeout=self.timeout,
        )

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000

        response_packet = response.content

        if show_visualization:
            console.print(f"[cyan]Received {len(response_packet)} bytes[/cyan]")

        response_payload = self.stack.decapsulate(response_packet)

        if response.status_code >= 400:
            raise RuntimeError(
                f"Server error ({response.status_code}): {response_payload.decode('utf-8', errors='replace')}"
            )

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

    def ping(self, count: int = 5) -> list[float]:
        """Send ping requests to measure latency.

        Args:
            count: Number of pings to send

        Returns:
            List of RTT measurements in milliseconds
        """
        rtts: list[float] = []

        console.print(
            f"\n[cyan]Pinging {self.base_url} ({count} times)...[/cyan]\n"
        )

        for i in range(count):
            client_time = str(time.time()).encode("utf-8")
            response, _ = self.send_receive(client_time, show_visualization=False)

            try:
                parts = response.decode("utf-8").split(",")
                sent_time = float(parts[0])
                received_time = time.time()

                rtt = (received_time - sent_time) * 1000
                rtts.append(rtt)

                console.print(f"[green]Ping {i + 1}:[/green] RTT = {rtt:.2f}ms")

            except (ValueError, IndexError) as e:
                console.print(f"[red]Error parsing ping response: {e}[/red]")

            if i < count - 1:
                time.sleep(0.5)

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

    def get_stats(self) -> dict[str, int | float]:
        """Get server statistics.

        Returns:
            Dictionary of server statistics
        """
        import json

        url = f"{self.base_url}/stats"
        response = self.session.get(url, timeout=self.timeout)
        response.raise_for_status()
        result = json.loads(response.text)
        return {k: v for k, v in result.items() if isinstance(v, (int, float))}

    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self) -> "HTTPClient":
        return self

    def __exit__(self, *args: Optional[object]) -> None:
        self.close()
