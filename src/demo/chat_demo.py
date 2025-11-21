"""Interactive chat demo for EoMacca protocol."""

from rich.console import Console

try:
    from ..client.tcp_client import TCPClient
    from ..client.ui import UI
except ImportError:
    from src.client.tcp_client import TCPClient  # type: ignore[no-redef]
    from src.client.ui import UI  # type: ignore[no-redef]

console = Console()


def main() -> None:
    """Run the chat demo."""
    ui = UI()
    ui.print_header("EoMacca Chat Demo")

    console.print("\n[dim]Make sure the server is running:[/dim]")
    console.print("[dim]  just server-tcp chat[/dim]\n")

    console.print(
        "[yellow]Type messages and press Enter. Type 'quit' to exit.[/yellow]\n"
    )

    client = TCPClient()

    while True:
        try:
            message = input("\033[32mYou>\033[0m ")

            if message.lower() in ("quit", "exit", "q"):
                console.print("[yellow]Goodbye![/yellow]")
                break

            if not message.strip():
                continue

            client.chat(message)

        except ConnectionRefusedError:
            ui.print_error("Connection refused. Is the server running?")
            break
        except KeyboardInterrupt:
            console.print("\n[yellow]Chat ended.[/yellow]")
            break
        except Exception as e:
            ui.print_error(f"Error: {e}")
            break


if __name__ == "__main__":
    main()
