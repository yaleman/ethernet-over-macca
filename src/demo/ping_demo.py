"""Ping/latency demo for EoMacca protocol."""

from rich.console import Console

from ..client.tcp_client import TCPClient
from ..client.ui import UI

console = Console()


def main() -> None:
    """Run the ping demo."""
    ui = UI()
    ui.print_header("EoMacca Latency Measurement Demo")

    console.print("\n[dim]Make sure the server is running:[/dim]")
    console.print("[dim]  just server-tcp ping[/dim]\n")

    client = TCPClient()

    try:
        rtts = client.ping(count=10)

        # Show comparison with typical network latency
        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
            console.print("\n[bold yellow]Latency Analysis:[/bold yellow]")
            console.print(
                f"  Average RTT through 8 layers: [cyan]{avg_rtt:.2f}ms[/cyan]"
            )
            console.print(
                f"  Estimated per-layer overhead: [cyan]{avg_rtt / 16:.2f}ms[/cyan] "
                "[dim](8 layers each way)[/dim]"
            )

    except ConnectionRefusedError:
        ui.print_error("Connection refused. Is the server running?")
    except Exception as e:
        ui.print_error(f"Error: {e}")


if __name__ == "__main__":
    main()
