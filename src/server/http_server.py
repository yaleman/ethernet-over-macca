"""HTTP/Flask server for EoMacca protocol."""

from typing import Literal

from flask import Flask, request, Response
from rich.console import Console

try:
    from ..protocol_stack import EoMaccaStack
    from .handlers import RequestHandler
except ImportError:
    from src.protocol_stack import EoMaccaStack  # type: ignore[no-redef]
    from src.server.handlers import RequestHandler  # type: ignore[no-redef]

console = Console()


class HTTPServer:
    """HTTP server implementing EoMacca RFC specification."""

    def __init__(self, mode: Literal["echo", "chat", "file", "ping"] = "echo") -> None:
        """Initialize HTTP server.

        Args:
            mode: Server mode (echo, chat, file, or ping)
        """
        self.mode = mode
        self.stack = EoMaccaStack()
        self.handler = RequestHandler()
        self.app = Flask(__name__)

        # Register routes
        self.app.route("/eomacca/v1/tunnel", methods=["POST"])(self.tunnel)
        self.app.route("/stats", methods=["GET"])(self.stats)

    def tunnel(self) -> Response:
        """Handle EoMacca tunnel endpoint (RFC Section 3.6)."""
        # Check content type
        if request.content_type != "application/dns-message":
            console.print(
                f"[yellow]Warning: Unexpected Content-Type: {request.content_type}[/yellow]"
            )

        # Get the HTTP body (which should be a DNS message per RFC)
        http_body = request.get_data()

        console.print(
            f"\n[cyan]HTTP Request:[/cyan] {len(http_body)} bytes "
            f"from {request.remote_addr}"
        )

        try:
            # The HTTP body contains DNS-encapsulated data
            # We need to extract it and continue decapsulating
            # For simplicity in this demo, we'll treat the whole HTTP request as the outer packet

            # In a real implementation, we'd reconstruct the full packet with Ethernet/IP/TCP headers
            # For now, we'll work with just the payload extraction

            # Reconstruct the full outer packet (simplified)
            # In production, you'd get this from the actual network interface
            full_packet = http_body  # Simplified

            # Decapsulate
            payload = self.stack.decapsulate(full_packet)

            console.print(f"[green]Decapsulated payload:[/green] {len(payload)} bytes")

            # Update statistics
            self.handler.stats.update_received(len(http_body), len(payload))

            # Handle request
            response_payload = self.handler.handle_request(payload, self.mode)

            # Encapsulate response
            response_packet = self.stack.encapsulate(response_payload)

            console.print(
                f"[cyan]Sending response:[/cyan] {len(response_packet)} bytes"
            )

            # Update statistics
            self.handler.stats.update_sent(len(response_packet))

            # Return as HTTP response
            return Response(
                response_packet,
                status=200,
                mimetype="application/dns-message",
                headers={"X-Layers": "too-many"},
            )

        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            error_msg = f"Error: {str(e)}".encode("utf-8")
            error_packet = self.stack.encapsulate(error_msg)

            return Response(
                error_packet, status=500, mimetype="application/dns-message"
            )

    def stats(self) -> dict[str, int | float]:
        """Return server statistics as JSON."""
        uptime = self.handler.stats.get_uptime()
        return {
            "uptime_seconds": uptime,
            "packets_received": self.handler.stats.packets_received,
            "packets_sent": self.handler.stats.packets_sent,
            "bytes_received": self.handler.stats.bytes_received,
            "bytes_sent": self.handler.stats.bytes_sent,
            "total_overhead": self.handler.stats.total_overhead,
        }

    def run(
        self, host: str = "127.0.0.1", port: int = 8080, debug: bool = False
    ) -> None:
        """Run the HTTP server.

        Args:
            host: Host to bind to
            port: Port to listen on
            debug: Enable debug mode
        """
        console.print("\n[bold cyan]EoMacca HTTP Server[/bold cyan]")
        console.print(f"Mode: [yellow]{self.mode.upper()}[/yellow]")
        console.print(f"Listening on [green]http://{host}:{port}[/green]")
        console.print("Endpoint: [green]POST /eomacca/v1/tunnel[/green]")
        console.print("Stats: [green]GET /stats[/green]")
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        self.app.run(host=host, port=port, debug=debug)


def main() -> None:
    """Run the HTTP server."""
    import sys

    mode: Literal["echo", "chat", "file", "ping"] = "echo"
    if len(sys.argv) > 1:
        mode = sys.argv[1]  # type: ignore[assignment]

    server = HTTPServer(mode=mode)
    try:
        server.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]Shutting down server...[/yellow]")
        server.handler.stats.display()


if __name__ == "__main__":
    main()
