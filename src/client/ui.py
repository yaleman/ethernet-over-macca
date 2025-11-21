"""Terminal UI utilities for EoMacca client."""

import time
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

console = Console()


class UI:
    """Terminal UI helper for EoMacca client."""

    @staticmethod
    def print_header(title: str) -> None:
        """Print a section header."""
        console.print(f"\n[bold cyan]{title}[/bold cyan]")
        console.print("=" * len(title))

    @staticmethod
    def print_packet_visualization(
        payload_size: int, encapsulated_size: int, layers: list[tuple[str, int]]
    ) -> None:
        """Visualize the packet encapsulation layers.

        Args:
            payload_size: Original payload size
            encapsulated_size: Final encapsulated size
            layers: List of (layer_name, size) tuples
        """
        tree = Tree("[bold]EoMacca Packet Structure[/bold]")

        current = tree
        for layer_name, size in layers:
            overhead = size - payload_size if size > payload_size else 0
            current = current.add(
                f"[cyan]{layer_name}[/cyan] ({size} bytes, +{overhead} overhead)"
            )

        current.add(f"[green]Payload[/green] ({payload_size} bytes)")

        console.print(tree)

        # Show efficiency
        efficiency = (
            (payload_size / encapsulated_size * 100) if encapsulated_size > 0 else 0
        )
        overhead_ratio = (
            ((encapsulated_size - payload_size) / payload_size)
            if payload_size > 0
            else 0
        )

        stats_table = Table(show_header=False, box=None)
        stats_table.add_row("Total Size:", f"{encapsulated_size} bytes")
        stats_table.add_row("Payload Size:", f"{payload_size} bytes")
        stats_table.add_row("Headers:", f"{encapsulated_size - payload_size} bytes")
        stats_table.add_row("Efficiency:", f"{efficiency:.2f}%")
        stats_table.add_row("Overhead Ratio:", f"{overhead_ratio:.2f}x")

        console.print(stats_table)

    @staticmethod
    def print_stats(stats: dict[str, Any]) -> None:
        """Print statistics in a formatted table."""
        table = Table(title="Statistics", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        for key, value in stats.items():
            if isinstance(value, float):
                table.add_row(key, f"{value:.2f}")
            elif isinstance(value, int):
                table.add_row(key, f"{value:,}")
            else:
                table.add_row(key, str(value))

        console.print(table)

    @staticmethod
    def print_success(message: str) -> None:
        """Print success message."""
        console.print(f"[bold green]✓[/bold green] {message}")

    @staticmethod
    def print_error(message: str) -> None:
        """Print error message."""
        console.print(f"[bold red]✗[/bold red] {message}")

    @staticmethod
    def print_info(message: str) -> None:
        """Print info message."""
        console.print(f"[blue]ℹ[/blue] {message}")

    @staticmethod
    def print_warning(message: str) -> None:
        """Print warning message."""
        console.print(f"[yellow]⚠[/yellow] {message}")

    @staticmethod
    def show_progress(description: str) -> Progress:
        """Create and return a progress spinner."""
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        )
        return progress

    @staticmethod
    def print_panel(content: str, title: str, style: str = "cyan") -> None:
        """Print content in a panel."""
        console.print(Panel(content, title=title, border_style=style))

    @staticmethod
    def measure_latency(func: Any, *args: Any, **kwargs: Any) -> tuple[Any, float]:
        """Measure function execution time.

        Returns:
            Tuple of (result, latency_ms)
        """
        start = time.perf_counter()
        result = func(*args, **kwargs)
        end = time.perf_counter()
        latency_ms = (end - start) * 1000
        return result, latency_ms
