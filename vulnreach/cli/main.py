"""
vulnreach — main CLI entry point.

Server lifecycle only (start / stop / reload / status). Scanning is not a CLI
concern — use the web UI, or call the API directly (see docs/ci-cd-gating.md
for a curl-based CI recipe).
"""

import click

from vulnreach.cli import lifecycle as _lifecycle_mod


@click.group()
@click.version_option(package_name="vulnreach")
def cli() -> None:
    """VulnReach — proves which CVEs are actually exploitable."""


cli.add_command(_lifecycle_mod.start)
cli.add_command(_lifecycle_mod.stop)
cli.add_command(_lifecycle_mod.reload)
cli.add_command(_lifecycle_mod.status)
