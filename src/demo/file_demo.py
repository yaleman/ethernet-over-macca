"""File transfer demo for EoMacca protocol."""

from ethernet_over_macca import get_logger

import tempfile
from pathlib import Path


from eom_client.tcp_client import TCPClient
from eom_client.ui import UI

CONSOLE = get_logger()


def main() -> None:
    """Run the file transfer demo."""
    ui = UI()
    ui.print_header("EoMacca File Transfer Demo")

    CONSOLE.print("\n[dim]Make sure the server is running:[/dim]")
    CONSOLE.print("[dim]  just server-tcp file[/dim]\n")

    client = TCPClient()

    # Create test files
    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Small file
        small_file = tmppath / "small.txt"
        small_file.write_text("Hello, this is a small test file!")

        # Medium file
        medium_file = tmppath / "medium.txt"
        medium_file.write_text("X" * 1000)  # 1KB

        # Large file
        large_file = tmppath / "large.txt"
        large_file.write_text("Y" * 10000)  # 10KB

        files = [small_file, medium_file, large_file]

        for file_path in files:
            try:
                CONSOLE.print(f"\n[cyan]Transferring {file_path.name}...[/cyan]")
                client.send_file(file_path)
                ui.print_success("Transfer complete!")

            except ConnectionRefusedError:
                ui.print_error("Connection refused. Is the server running?")
                return
            except Exception as e:
                ui.print_error(f"Error: {e}")
                return

    CONSOLE.print("\n[bold green]File transfer demo complete![/bold green]")
    CONSOLE.print(
        "[dim]Notice how the overhead increases dramatically for small files![/dim]"
    )


if __name__ == "__main__":
    main()
