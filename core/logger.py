"""
Recon47 - Custom Logger Module
Author: Xaff
Rich-based console output with colored status indicators and formatted displays.
"""

import sys
import os
import io

# Force UTF-8 encoding on Windows to support Unicode symbols
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
try:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
except Exception:
    pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box
import time

console = Console(force_terminal=True)


class Logger:
    """Custom logger providing styled console output for Recon47."""

    BANNER = r"""
[bold green]
    ____                        __ __  ______
   / __ \___  _________  ____  / // / /__  __/
  / /_/ / _ \/ ___/ __ \/ __ \/ // /_   / /   
 / _, _/  __/ /__/ /_/ / / / /__  __/  / /    
/_/ |_|\___/\___/\____/_/ /_/  /_/    /_/     
[/bold green]
[bold cyan]  ═══════════════════════════════════════════[/bold cyan]
[bold white]  🔱 Automated Recon & Vulnerability Scanner[/bold white]
[bold dim]  Version 1.0.0 | Author: Xaff[/bold dim]
[bold cyan]  ═══════════════════════════════════════════[/bold cyan]
"""

    @staticmethod
    def banner():
        """Display the Recon47 ASCII banner."""
        console.print(Logger.BANNER)

    @staticmethod
    def phase(title, icon="🔍"):
        """Display a phase header with a boxed title."""
        console.print()
        console.print(Panel(
            f"[bold white]{title}[/bold white]",
            title=f"[bold cyan]{icon} PHASE[/bold cyan]",
            border_style="cyan",
            box=box.DOUBLE_EDGE,
            padding=(0, 2)
        ))

    @staticmethod
    def module(name, description=""):
        """Display a module start header."""
        desc = f" — [dim]{description}[/dim]" if description else ""
        console.print(f"\n  [bold yellow]▶[/bold yellow] [bold white]{name}[/bold white]{desc}")

    @staticmethod
    def success(message):
        """Display a success message."""
        console.print(f"    [bold green]✓[/bold green] {message}")

    @staticmethod
    def error(message):
        """Display an error message."""
        console.print(f"    [bold red]✗[/bold red] [red]{message}[/red]")

    @staticmethod
    def warning(message):
        """Display a warning message."""
        console.print(f"    [bold yellow]⚠[/bold yellow] [yellow]{message}[/yellow]")

    @staticmethod
    def info(message):
        """Display an info message."""
        console.print(f"    [bold blue]ℹ[/bold blue] {message}")

    @staticmethod
    def found(item, detail=""):
        """Display a found item."""
        det = f" [dim]({detail})[/dim]" if detail else ""
        console.print(f"    [bold green]»[/bold green] [white]{item}[/white]{det}")

    @staticmethod
    def vuln(severity, title, detail=""):
        """Display a vulnerability finding with severity color."""
        colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim"
        }
        color = colors.get(severity.upper(), "white")
        det = f"\n      [dim]{detail}[/dim]" if detail else ""
        console.print(f"    [{color}]⦿ [{severity.upper()}][/{color}] {title}{det}")

    @staticmethod
    def table(title, columns, rows):
        """Display a formatted Rich table."""
        table = Table(
            title=f"[bold cyan]{title}[/bold cyan]",
            box=box.ROUNDED,
            border_style="dim cyan",
            header_style="bold white",
            show_lines=True,
            padding=(0, 1)
        )
        for col in columns:
            table.add_column(col, style="white")
        for row in rows:
            table.add_row(*[str(cell) for cell in row])
        console.print()
        console.print(table)

    @staticmethod
    def summary_panel(title, content):
        """Display a summary panel with key-value pairs."""
        text = ""
        for key, value in content.items():
            text += f"[bold cyan]{key}:[/bold cyan] [white]{value}[/white]\n"
        console.print(Panel(
            text.strip(),
            title=f"[bold green]{title}[/bold green]",
            border_style="green",
            box=box.ROUNDED,
            padding=(0, 2)
        ))

    @staticmethod
    def progress(description="Scanning"):
        """Return a Rich progress bar context manager."""
        return Progress(
            SpinnerColumn("dots", style="cyan"),
            TextColumn("[bold white]{task.description}"),
            BarColumn(bar_width=30, style="cyan", complete_style="green"),
            TextColumn("[bold green]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        )

    @staticmethod
    def separator():
        """Display a separator line."""
        console.print("[dim cyan]  ─────────────────────────────────────────────[/dim cyan]")

    @staticmethod
    def scan_complete(duration, output_path):
        """Display scan completion summary."""
        console.print()
        console.print(Panel(
            f"[bold green]✓ Scan completed successfully![/bold green]\n"
            f"[white]Duration: [bold]{duration:.1f}s[/bold][/white]\n"
            f"[white]Report:   [bold cyan]{output_path}[/bold cyan][/white]",
            title="[bold green]🔱 RECON47 COMPLETE[/bold green]",
            border_style="green",
            box=box.DOUBLE_EDGE,
            padding=(1, 2)
        ))

    @staticmethod
    def disclaimer():
        """Display ethical use disclaimer."""
        console.print(Panel(
            "[bold yellow]⚠ DISCLAIMER[/bold yellow]\n"
            "[white]This tool is intended for authorized security testing only.\n"
            "Only scan targets you have explicit permission to test.\n"
            "The author assumes no liability for misuse of this tool.[/white]",
            border_style="yellow",
            box=box.HEAVY,
            padding=(0, 2)
        ))
