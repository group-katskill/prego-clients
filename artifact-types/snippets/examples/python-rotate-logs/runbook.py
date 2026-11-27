#!/usr/bin/env python3
"""Remove .log files older than a number of days from one folder.

Use --dry-run first: it shows the files and removes nothing. The runbook does not follow symlinks and does not go
into subfolders.
"""
import time
from pathlib import Path

import click


@click.command()
@click.option("--dir", "log_dir", default="/var/log/myapp", show_default=True,
              type=click.Path(exists=True, file_okay=False, path_type=Path), help="The folder with the log files.")
@click.option("--days", default=14, show_default=True, type=click.IntRange(min=1),
              help="Remove files older than this number of days.")
@click.option("--dry-run", is_flag=True, help="Show the files and remove nothing.")
def main(log_dir: Path, days: int, dry_run: bool) -> None:
    cutoff = time.time() - days * 86400
    old = sorted(p for p in log_dir.glob("*.log")
                 if p.is_file() and not p.is_symlink() and p.stat().st_mtime < cutoff)
    for p in old:
        click.echo(f"{'would remove' if dry_run else 'remove'} {p}")
        if not dry_run:
            p.unlink()
    click.echo(f"{len(old)} file(s) older than {days} days in {log_dir}{' (dry run)' if dry_run else ''}")


if __name__ == "__main__":
    main()
