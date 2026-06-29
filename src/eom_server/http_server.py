"""HTTP/Flask server for EoMacca protocol."""

import sys
import time

import threading
from typing import Literal

from flask import Flask, request, Response
from werkzeug.serving import make_server

from ethernet_over_macca import get_logger
from ethernet_over_macca.protocol_stack import EoMaccaStack

from .handlers import RequestHandler

CONSOLE = get_logger()


class HTTPServer:
    """HTTP server implementing EoMacca RFC specification."""

    def __init__(self, mode: Literal["echo", "chat", "file", "ping"] = "echo") -> None:
        """Initialize HTTP server.

        Args:
            mode: Server mode (echo, chat, file, or ping)
        """
        self.mode = mode
        self.port = 0
        self.stack = EoMaccaStack()
        self.handler = RequestHandler()
        self.app = Flask(__name__)

        self.app.route("/eomacca/v1/tunnel", methods=["POST"])(self.tunnel)
        self.app.route("/stats", methods=["GET"])(self.stats)

    def tunnel(self) -> Response:
        """Handle EoMacca tunnel endpoint (RFC Section 3.6)."""
        if request.content_type != "application/dns-message":
            CONSOLE.print(
                f"[yellow]Warning: Unexpected Content-Type: {request.content_type}[/yellow]"
            )

        http_body = request.get_data()

        CONSOLE.print(
            f"\n[cyan]HTTP Request:[/cyan] {len(http_body)} bytes "
            f"from {request.remote_addr}"
        )

        try:
            payload = self.stack.decapsulate(http_body)

            self.handler.stats.update_received(len(http_body), len(payload))

            response_payload = self.handler.handle_request(payload, self.mode)

            response_packet = self.stack.encapsulate(response_payload)

            CONSOLE.print(
                f"[cyan]Sending response:[/cyan] {len(response_packet)} bytes"
            )

            self.handler.stats.update_sent(len(response_packet))

            return Response(
                response_packet,
                status=200,
                mimetype="application/dns-message",
                headers={"X-Layers": "too-many"},
            )

        except Exception as e:
            CONSOLE.print(f"[bold red]Error:[/bold red] {e}")
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
            port: Port to listen on (0 for OS-assigned)
            debug: Enable debug mode
        """
        self.port = port
        CONSOLE.print("\n[bold cyan]EoMacca HTTP Server[/bold cyan]")
        CONSOLE.print(f"Mode: [yellow]{self.mode.upper()}[/yellow]")
        CONSOLE.print(f"Listening on [green]http://{host}:{port}[/green]")
        CONSOLE.print("Endpoint: [green]POST /eomacca/v1/tunnel[/green]")
        CONSOLE.print("Stats: [green]GET /stats[/green]")
        CONSOLE.print("[dim]Press Ctrl+C to stop[/dim]\n")

        self.app.run(host=host, port=port, debug=debug)

    def run_in_thread(
        self, host: str = "127.0.0.1", port: int = 0, max_startup_secs: float = 5.0
    ) -> threading.Thread:
        """Start the HTTP server in a background thread with OS-assigned port.

        Returns the thread. The assigned port is available as self.port after
        the server starts listening.
        """
        self._server_thread = threading.Thread(
            target=self._run_server, args=(host, port), daemon=True
        )
        self._server_thread.start()
        time_to_throw_error = time.time() + max_startup_secs
        while True:
            if self.port != 0:
                break
            time.sleep(0.1)
            if time.time() > time_to_throw_error:
                raise RuntimeError(
                    f"Server failed to start in {max_startup_secs}s and assign a port!"
                )
        return self._server_thread

    def _run_server(self, host: str, port: int) -> None:
        """Run the server and capture the assigned port."""

        self._werkzeug_server = make_server(host, port, self.app)
        self.port = self._werkzeug_server.socket.getsockname()[1]
        self._werkzeug_server.serve_forever()

    def stop(self) -> None:
        """Stop the server started with run_in_thread."""
        if hasattr(self, "_werkzeug_server"):
            self._werkzeug_server.shutdown()


if __name__ == "__main__":
    """Run the HTTP server."""

    mode: Literal["echo", "chat", "file", "ping"] = "echo"
    if len(sys.argv) > 1:
        mode = sys.argv[1]  # type: ignore[assignment]  # ty:ignore[invalid-assignment]

    server = HTTPServer(mode=mode)
    try:
        server.run()
    except KeyboardInterrupt:
        CONSOLE.print("\n[yellow]Shutting down server...[/yellow]")
        server.handler.stats.display()
