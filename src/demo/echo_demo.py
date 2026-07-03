"""Echo demo for EoMacca protocol."""

from ethernet_over_macca import get_logger

from ethernet_over_macca.cli import parse_demo_layer_order
from eom_client.tcp_client import TCPClient
from eom_client.ui import UI

CONSOLE = get_logger()


def main() -> None:
    """Run the echo demo."""
    ui = UI()
    ui.print_header("EoMacca Echo Demo")

    layer_order = parse_demo_layer_order("demo.echo_demo")

    CONSOLE.print("\n[dim]Make sure the server is running:[/dim]")
    if layer_order is None:
        CONSOLE.print("[dim]  just server-tcp echo[/dim]\n")
    else:
        CONSOLE.print(f"[dim]  just server-tcp echo --layers {layer_order}[/dim]\n")

    client = TCPClient(layer_order=layer_order)

    # Test messages
    messages = [
        "Hello, EoMacca!",
        "This is a test of the 8-layer protocol stack",
        "The overhead is ridiculous but it works!",
    ]

    for i, message in enumerate(messages, 1):
        CONSOLE.print(f"\n[bold cyan]Test {i}:[/bold cyan]")
        CONSOLE.print(f"[yellow]Sending:[/yellow] {message}")

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

    CONSOLE.print("\n[bold green]Echo demo complete![/bold green]")


if __name__ == "__main__":
    main()
