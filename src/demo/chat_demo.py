"""Interactive chat demo for EoMacca protocol."""

from ethernet_over_macca import get_logger
from eom_client.tcp_client import TCPClient
from eom_client.ui import UI


CONSOLE = get_logger()


def main() -> None:
    """Run the chat demo."""
    ui = UI()
    ui.print_header("EoMacca Chat Demo")

    CONSOLE.print("[dim]Make sure the server is running:[/dim]")
    CONSOLE.print("[dim]  just server-tcp chat[/dim]\n")

    CONSOLE.print(
        "[yellow]Type messages and press Enter. Type 'quit' to exit.[/yellow]\n"
    )

    client = TCPClient()

    while True:
        try:
            message = input("\033[32mYou>\033[0m ")

            if message.lower() in ("quit", "exit", "q"):
                CONSOLE.print("[yellow]Goodbye![/yellow]")
                break

            if not message.strip():
                continue

            client.chat(message)

        except ConnectionRefusedError:
            ui.print_error("Connection refused. Is the server running?")
            break
        except KeyboardInterrupt:
            CONSOLE.print("\n[yellow]Chat ended.[/yellow]")
            break
        except Exception as e:
            ui.print_error(f"Error: {e}")
            break


if __name__ == "__main__":
    main()
