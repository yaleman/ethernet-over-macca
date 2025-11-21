"""File transfer demo for EoMacca protocol."""

import tempfile
from pathlib import Path

from rich.console import Console

from ..client.tcp_client import TCPClient
from ..client.ui import UI

console = Console()


def main() -> None:
    """Run the file transfer demo."""
    ui = UI()
    ui.print_header("EoMacca File Transfer Demo")

    console.print("\n[dim]Make sure the server is running:[/dim]")
    console.print("[dim]  just server-tcp file[/dim]\n")

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
                console.print(f"\n[cyan]Transferring {file_path.name}...[/cyan]")
                client.send_file(file_path)
                ui.print_success("Transfer complete!")

            except ConnectionRefusedError:
                ui.print_error("Connection refused. Is the server running?")
                return
            except Exception as e:
                ui.print_error(f"Error: {e}")
                return

    console.print("\n[bold green]File transfer demo complete![/bold green]")
    console.print(
        "[dim]Notice how the overhead increases dramatically for small files![/dim]"
    )


if __name__ == "__main__":
    main()
