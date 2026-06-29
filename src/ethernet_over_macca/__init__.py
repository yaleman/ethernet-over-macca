import sys
from rich.console import Console


MAX_FILENAME_LENGTH = 4096


def get_logger() -> Console:
    """Get a console logger that respects pytest's output capture."""

    pytest_running = "pytest" in sys.modules
    return Console(
        force_terminal=None if not pytest_running else False,
        file=sys.stdout if not pytest_running else sys.stderr,
        stderr=pytest_running,
        force_interactive=not pytest_running,
    )
