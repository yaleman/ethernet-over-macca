"""TCP socket server for EoMacca protocol."""

from eom_client import UI

import sys

import atexit
import signal
import socket
import struct
import threading
from typing import Literal

from ethernet_over_macca import get_logger
from ethernet_over_macca.protocol_stack import EoMaccaStack
from .handlers import RequestHandler

CONSOLE = get_logger()

MAX_PACKET_SIZE = 102 * 1024 * 1024  # 102MB max packet size


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket, raising on disconnect."""
    data = bytearray()
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError(
                f"Connection closed while receiving data from client: laddr={sock.getsockname()} raddr={sock.getpeername()}"
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
        CONSOLE.print(f"\n[bold green]New connection from {address}[/bold green]")

        try:
            data = recv_packet(client_socket)
            if not data:
                CONSOLE.print(f"[yellow]Client {address} disconnected[/yellow]")
                return

            CONSOLE.print(f"[cyan]Received packet:[/cyan] {len(data)} bytes")

            payload = self.stack.decapsulate(data)
            CONSOLE.print(f"[green]Decapsulated payload:[/green] {len(payload)} bytes")

            self.handler.stats.update_received(len(data), len(payload))

            response_payload = self.handler.handle_request(payload, self.mode)

            response_packet = self.stack.encapsulate(response_payload)
            CONSOLE.print(
                f"[cyan]Sending response:[/cyan] {len(response_packet)} bytes"
            )

            send_packet(client_socket, response_packet)

            self.handler.stats.update_sent(len(response_packet), len(response_payload))
        except ConnectionError:
            CONSOLE.print(f"[yellow]Client {address} disconnected[/yellow]")
            return
        except Exception as e:
            CONSOLE.print(f"[bold red]Error processing packet:[/bold red] {e}")
            try:
                error_msg = f"Error: {str(e)}".encode("utf-8")
                error_packet = self.stack.encapsulate(error_msg)
                send_packet(client_socket, error_packet)
            except Exception as e:
                if "pytest" in sys.modules:
                    # because it's shutting down, we don't want to raise an exception in pytest because the logger has been closed
                    return
                raise e

        finally:
            client_socket.close()

    def shutdown(self) -> None:
        try:
            CONSOLE.print("\n[yellow]Shutting down server...[/yellow]")
        except Exception:
            if "pytest" in sys.modules:
                return
            print("\nShutting down server...")
        self.handler.stats.display()
        self.running = False

    def start(self) -> None:
        """Start the TCP server."""
        self.running = True

        atexit.register(self.shutdown)
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, lambda *_: self.shutdown())

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.host, self.port))
            self.port = server_socket.getsockname()[1]
            server_socket.listen(5)

            CONSOLE.print("\n[bold cyan]EoMacca TCP Server[/bold cyan]")
            CONSOLE.print(f"Mode: [yellow]{self.mode.upper()}[/yellow]")
            CONSOLE.print(f"Listening on [green]{self.host}:{self.port}[/green]")
            CONSOLE.print("[dim]Press Ctrl+C to stop[/dim]\n")

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
                self.running = False


def main() -> None:
    """Run the TCP server."""

    UI()
    mode = sys.argv[1] if len(sys.argv) > 1 else "echo"
    server = TCPServer(mode=mode)  # type: ignore[arg-type]  # ty:ignore[invalid-argument-type]
    server.start()


if __name__ == "__main__":
    main()
