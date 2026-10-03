"""vulnreach start / stop / reload / status — server lifecycle only.

Scanning is not a CLI concern: use the web UI or call the API directly
(see docs/ci-cd-gating.md for a curl-based CI recipe).
"""
from __future__ import annotations

from typing import Optional

import click
from rich.console import Console

from vulnreach import lifecycle

console = Console()

_mode_option = click.option(
    "--mode",
    type=click.Choice(["docker", "process"]),
    default=None,
    help="Force a lifecycle mode instead of auto-detecting.",
)
_compose_option = click.option(
    "--compose-file",
    default=lifecycle.DEFAULT_COMPOSE_FILE,
    show_default=True,
    help="docker-compose file to use in docker mode.",
)


def _resolve_mode(mode: Optional[str], compose_file: str) -> str:
    return mode or lifecycle.detect_mode(compose_file)


@click.command()
@_mode_option
@_compose_option
@click.option("--host", default=lifecycle.DEFAULT_HOST, show_default=True, help="Process mode only.")
@click.option("--port", default=lifecycle.DEFAULT_PORT, show_default=True, help="Process mode only.")
def start(mode: Optional[str], compose_file: str, host: str, port: int) -> None:
    """Start the VulnReach server (Docker or bare process, auto-detected)."""
    resolved = _resolve_mode(mode, compose_file)
    try:
        if resolved == "docker":
            lifecycle.docker_start(compose_file=compose_file)
            console.print(f"[green]Started[/green] (docker compose, {compose_file}) — http://localhost:8000")
        else:
            pid = lifecycle.process_start(host=host, port=port)
            console.print(f"[green]Started[/green] (pid {pid}) — http://{host}:{port}")
    except lifecycle.LifecycleError as exc:
        console.print(f"[red]Failed to start:[/red] {exc}")
        raise SystemExit(1)


@click.command()
@_mode_option
@_compose_option
def stop(mode: Optional[str], compose_file: str) -> None:
    """Stop the VulnReach server."""
    resolved = _resolve_mode(mode, compose_file)
    try:
        if resolved == "docker":
            lifecycle.docker_stop(compose_file=compose_file)
        else:
            lifecycle.process_stop()
        console.print("[green]Stopped[/green]")
    except lifecycle.LifecycleError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        raise SystemExit(1)


@click.command()
@_mode_option
@_compose_option
@click.option("--host", default=lifecycle.DEFAULT_HOST, show_default=True, help="Process mode only.")
@click.option("--port", default=lifecycle.DEFAULT_PORT, show_default=True, help="Process mode only.")
def reload(mode: Optional[str], compose_file: str, host: str, port: int) -> None:
    """Restart the VulnReach server with the current config.

    This is a restart, not a zero-downtime reload — there's a brief gap while
    the process (or container) comes back up.
    """
    resolved = _resolve_mode(mode, compose_file)
    try:
        if resolved == "docker":
            lifecycle.docker_reload(compose_file=compose_file)
            console.print(f"[green]Reloaded[/green] (docker compose, {compose_file})")
        else:
            pid = lifecycle.process_reload(host=host, port=port)
            console.print(f"[green]Reloaded[/green] (pid {pid})")
    except lifecycle.LifecycleError as exc:
        console.print(f"[red]Failed to reload:[/red] {exc}")
        raise SystemExit(1)


@click.command()
@_mode_option
@_compose_option
def status(mode: Optional[str], compose_file: str) -> None:
    """Show whether the VulnReach server is running."""
    resolved = _resolve_mode(mode, compose_file)
    if resolved == "docker":
        console.print(lifecycle.docker_status(compose_file=compose_file))
    else:
        console.print(lifecycle.process_status())
