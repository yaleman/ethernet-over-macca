"""Ping/latency demo for EoMacca protocol."""

from ethernet_over_macca import get_logger
from eom_client.tcp_client import TCPClient
from eom_client.ui import UI

CONSOLE = get_logger()


def main() -> None:
    """Run the ping demo."""
    ui = UI()
    ui.print_header("EoMacca Ping Demo")

    client = TCPClient()

    try:
        rtts = client.ping(count=10)

        # Show comparison with typical network latency
        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
            ui.print_warning("Latency Analysis:")
            CONSOLE.print(
                f"  Average RTT through 8 layers: [cyan]{avg_rtt:.2f}ms[/cyan]"
            )
            CONSOLE.print(
                f"  Estimated per-layer overhead: [cyan]{avg_rtt / 16:.2f}ms[/cyan] "
            )
            CONSOLE.print("   [dim](8 layers each way)[/dim]")

    except ConnectionRefusedError:
        ui.print_error("Make sure the server is running:")
        ui.print_error("    just server-tcp ping")
        ui.print_error("Connection refused. Is the server running?")
    except Exception as e:
        ui.print_error("Make sure the server is running:")
        ui.print_error("    just server-tcp ping")
        ui.print_error(f"Error: {e}")


if __name__ == "__main__":
    main()
