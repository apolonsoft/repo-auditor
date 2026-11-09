from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from repo_auditor.models import AuditReport, Severity

console = Console()


def render_report(report: AuditReport) -> None:
    console.print()
    console.print(
        Panel.fit(
            f"[bold cyan]Repo Auditor Security Report[/bold cyan]\nTarget: [white]{report.target_path.resolve()}[/white]",
            border_style="cyan",
        )
    )

    if not report.findings:
        console.print(
            Panel(
                "[bold green]✔ Clean Repository![/bold green] No dangerous packages, rogue registries, or malicious patterns detected.",
                border_style="green",
            )
        )
        return

    # Display findings in a rich table
    table = Table(title="Detected Security Findings", show_header=True, header_style="bold magenta")
    table.add_column("Severity", justify="center", width=12)
    table.add_column("Category", width=22)
    table.add_column("Finding", style="white")
    table.add_column("Location", style="dim", width=30)

    # Order findings: CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    sorted_findings = sorted(report.findings, key=lambda f: severity_order[f.severity])

    for f in sorted_findings:
        loc = ""
        if f.file_path:
            loc = f.file_path.name
            if f.line_number:
                loc += f":{f.line_number}"

        desc = f"[bold]{f.title}[/bold]\n{f.description}"
        if f.snippet:
            desc += f"\n[dim italic]{f.snippet}[/dim italic]"

        table.add_row(
            f"[{f.severity.color}]{f.severity.value}[/{f.severity.color}]",
            f.category,
            desc,
            loc,
        )

    console.print(table)
    console.print()

    # Summary box
    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column(style="bold")
    summary_table.add_column()

    summary_table.add_row("Critical:", f"[bold red]{report.critical_count}[/bold red]")
    summary_table.add_row("High:", f"[red]{report.high_count}[/red]")
    summary_table.add_row("Medium:", f"[yellow]{report.medium_count}[/yellow]")
    summary_table.add_row("Low:", f"[blue]{report.low_count}[/blue]")

    console.print(
        Panel(
            summary_table,
            title="[bold]Summary[/bold]",
            border_style="red" if report.has_threats else "yellow",
        )
    )
