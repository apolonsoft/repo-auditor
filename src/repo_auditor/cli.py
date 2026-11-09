from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from repo_auditor.models import AuditReport
from repo_auditor.remote import fetch_remote_repo_in_memory, parse_github_target
from repo_auditor.reporter import render_report
from repo_auditor.scanners.code import audit_javascript_files
from repo_auditor.scanners.npm import scan_npm_ecosystem
from repo_auditor.scanners.php import scan_php_ecosystem
from repo_auditor.scanners.python import scan_python_ecosystem

app = typer.Typer(
    name="repo-auditor",
    help="Audit GitHub and local codebases for malware, dangerous packages, and risky hooks.",
    add_completion=False,
)
console = Console()


def run_scanners(target_path: Path, report: AuditReport) -> None:
    # 1. npm ecosystem (npmrc, package.json hooks, sources, lockfiles, OSV)
    scan_npm_ecosystem(target_path, report)

    # 2. Python ecosystem (requirements, setup.py, AST, OSV)
    scan_python_ecosystem(target_path, report)

    # 3. PHP & Composer ecosystem (composer.json, composer.lock, PHP heuristics, OSV)
    scan_php_ecosystem(target_path, report)

    # 4. JavaScript / TypeScript code heuristics
    audit_javascript_files(target_path, report)


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Argument(
            help="Directory path OR remote GitHub URL / 'owner/repo' shorthand.",
        ),
    ] = ".",
    strict: Annotated[
        bool,
        typer.Option(
            "--strict",
            "-s",
            help="Fail with exit code 1 if Critical or High severity findings are detected.",
        ),
    ] = False,
    token: Annotated[
        str | None,
        typer.Option(
            "--token",
            "-t",
            help="Optional GitHub Personal Access Token (for private repos or rate-limits).",
            envvar="GITHUB_TOKEN",
        ),
    ] = None,
) -> None:
    """Scan a target repository (local folder or remote GitHub repo) for threats."""
    gh_info = parse_github_target(target)

    if gh_info:
        owner, repo_name = gh_info
        console.print(
            f"[bold cyan]Fetching remote repository in-memory:[/bold cyan] [yellow]{owner}/{repo_name}[/yellow] (no git clone)"
        )
        report = AuditReport(target_path=Path(f"github.com/{owner}/{repo_name}"))

        with console.status(
            "[bold cyan]Downloading repository archive into memory...[/bold cyan]", spinner="dots"
        ):
            try:
                with fetch_remote_repo_in_memory(owner, repo_name, token=token) as remote_dir:
                    run_scanners(remote_dir, report)
            except Exception as e:
                console.print(f"[bold red]Error fetching remote repository:[/bold red] {e}")
                raise typer.Exit(code=1) from e
    else:
        local_path = Path(target).resolve()
        if not local_path.exists() or not local_path.is_dir():
            console.print(f"[bold red]Error:[/bold red] Target directory does not exist: {target}")
            raise typer.Exit(code=1)

        report = AuditReport(target_path=local_path)
        with console.status(
            f"[bold cyan]Auditing local repository at {local_path}...[/bold cyan]", spinner="dots"
        ):
            run_scanners(local_path, report)

    render_report(report)

    if strict and report.has_threats:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
