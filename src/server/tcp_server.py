"""TCP socket server for EoMacca protocol."""

import socket
import threading
from typing import Literal

from rich.console import Console

try:
    from ..protocol_stack import EoMaccaStack
    from .handlers import RequestHandler
except ImportError:
    from src.protocol_stack import EoMaccaStack  # type: ignore[no-redef]
    from src.server.handlers import RequestHandler  # type: ignore[no-redef]

console = Console()


class TCPServer:
    """TCP server that handles EoMacca packets."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9999,
        mode: Literal["echo", "chat", "file", "ping"] = "echo",
    ) -> None:
        """Initialize TCP server.

        Args:
            host: Host to bind to
            port: Port to listen on
            mode: Server mode (echo, chat, file, or ping)
        """
        self.host = host
        self.port = port
        self.mode = mode
        self.stack = EoMaccaStack()
        self.handler = RequestHandler()
        self.running = False

    def handle_client(
        self, client_socket: socket.socket, address: tuple[str, int]
    ) -> None:
        """Handle a client connection.

        Args:
            client_socket: Client socket
            address: Client address
        """
        console.print(f"\n[bold green]New connection from {address}[/bold green]")

        try:
            # Receive data (up to 64KB)
            data = client_socket.recv(65536)
            if not data:
                console.print(f"[yellow]Client {address} disconnected[/yellow]")
                return

            console.print(f"[cyan]Received packet:[/cyan] {len(data)} bytes")

            # Decapsulate the EoMacca packet
            try:
                payload = self.stack.decapsulate(data)
                console.print(
                    f"[green]Decapsulated payload:[/green] {len(payload)} bytes"
                )

                # Update statistics
                self.handler.stats.update_received(len(data), len(payload))

                # Handle the request based on mode
                response_payload = self.handler.handle_request(payload, self.mode)

                # Encapsulate response
                response_packet = self.stack.encapsulate(response_payload)
                console.print(
                    f"[cyan]Sending response:[/cyan] {len(response_packet)} bytes"
                )

                # Send response
                client_socket.sendall(response_packet)

                # Update statistics
                self.handler.stats.update_sent(len(response_packet))

            except Exception as e:
                console.print(f"[bold red]Error processing packet:[/bold red] {e}")
                error_msg = f"Error: {str(e)}".encode("utf-8")
                error_packet = self.stack.encapsulate(error_msg)
                client_socket.sendall(error_packet)

        finally:
            client_socket.close()
            console.print(f"[dim]Connection closed: {address}[/dim]")

    def start(self) -> None:
        """Start the TCP server."""
        self.running = True

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)

            console.print("\n[bold cyan]EoMacca TCP Server[/bold cyan]")
            console.print(f"Mode: [yellow]{self.mode.upper()}[/yellow]")
            console.print(f"Listening on [green]{self.host}:{self.port}[/green]")
            console.print("[dim]Press Ctrl+C to stop[/dim]\n")

            try:
                while self.running:
                    try:
                        # Set timeout so we can check running flag
                        server_socket.settimeout(1.0)
                        client_socket, address = server_socket.accept()

                        # Handle client in a new thread
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, address),
                            daemon=True,
                        )
                        client_thread.start()

                    except socket.timeout:
                        continue

            except KeyboardInterrupt:
                console.print("\n[yellow]Shutting down server...[/yellow]")
                self.handler.stats.display()
                self.running = False


def main() -> None:
    """Run the TCP server."""
    import sys

    mode: Literal["echo", "chat", "file", "ping"] = "echo"
    if len(sys.argv) > 1:
        mode = sys.argv[1]  # type: ignore[assignment]

    server = TCPServer(mode=mode)
    server.start()


if __name__ == "__main__":
    main()
