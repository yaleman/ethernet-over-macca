"""Ping/latency demo for EoMacca protocol."""

from ethernet_over_macca import get_logger
from ethernet_over_macca.cli import parse_demo_layer_order
from eom_client.tcp_client import TCPClient
from eom_client.ui import UI

CONSOLE = get_logger()


def main() -> None:
    """Run the ping demo."""
    ui = UI()
    ui.print_header("EoMacca Ping Demo")

    layer_order = parse_demo_layer_order("demo.ping_demo")

    if layer_order is None:
        CONSOLE.print(
            "[dim]Make sure the server is running: just server-tcp ping[/dim]\n"
        )
    else:
        CONSOLE.print(
            f"[dim]Make sure the server is running: "
            f"just server-tcp ping --layers {layer_order}[/dim]\n"
        )

    client = TCPClient(layer_order=layer_order)

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
