"""Echo demo for EoMacca protocol."""

from rich.console import Console

try:
    from ..client.tcp_client import TCPClient
    from ..client.ui import UI
except ImportError:
    from src.client.tcp_client import TCPClient  # type: ignore[no-redef]
    from src.client.ui import UI  # type: ignore[no-redef]

console = Console()


def main() -> None:
    """Run the echo demo."""
    ui = UI()
    ui.print_header("EoMacca Echo Demo")

    console.print("\n[dim]Make sure the server is running:[/dim]")
    console.print("[dim]  just server-tcp echo[/dim]\n")

    client = TCPClient()

    # Test messages
    messages = [
        "Hello, EoMacca!",
        "This is a test of the 8-layer protocol stack",
        "The overhead is ridiculous but it works!",
    ]

    for i, message in enumerate(messages, 1):
        console.print(f"\n[bold cyan]Test {i}:[/bold cyan]")
        console.print(f"[yellow]Sending:[/yellow] {message}")

        try:
            response = client.echo(message)
            if response == message:
                ui.print_success(f"Echo successful! Got back: {response}")
            else:
                ui.print_error(f"Mismatch! Expected: {message}, Got: {response}")
        except ConnectionRefusedError:
            ui.print_error("Connection refused. Is the server running?")
            return
        except Exception as e:
            ui.print_error(f"Error: {e}")
            return

    console.print("\n[bold green]Echo demo complete![/bold green]")


if __name__ == "__main__":
    main()
