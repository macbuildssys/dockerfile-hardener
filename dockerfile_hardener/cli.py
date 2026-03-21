"""
CLI entry point for dockerfile-hardener.

Commands:
  lint  — check a Dockerfile and report findings
  fix   — apply auto-fixable findings in-place
  rules — list all available rules
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from dockerfile_hardener import __version__
from dockerfile_hardener.fixer import Fixer
from dockerfile_hardener.parser import parse_dockerfile
from dockerfile_hardener.reporter import (
    report_html,
    report_json,
    report_sarif,
    report_table,
)
from dockerfile_hardener.rules import ALL_RULES
from dockerfile_hardener.rules.base import Finding, RuleResult, Severity

# helpers

def _gather_findings(dockerfile_path: str) -> tuple[list[RuleResult], list[Finding]]:
    """Parse the Dockerfile and run all rules. Returns (results, all_findings)."""
    parsed = parse_dockerfile(dockerfile_path)
    results = [rule.check(parsed) for rule in ALL_RULES]
    all_findings = [f for r in results for f in r.findings]
    return results, all_findings


def _severity_from_str(value: str) -> Severity:
    try:
        return Severity(value.upper())
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        raise click.BadParameter(f"Must be one of: {valid}")

#  CLI root

@click.group()
@click.version_option(__version__, "--version", "-V", message="%(version)s")
def main():
    """
    \b
    dockerfile-hardener — lint and auto-fix Dockerfiles.

    \b
    Examples:
      dockerfile-hardener lint Dockerfile
      dockerfile-hardener lint Dockerfile --format html -o report.html
      dockerfile-hardener fix  Dockerfile --dry-run
      dockerfile-hardener rules
    """

#  lint

@main.command("lint")
@click.argument("dockerfile", default="Dockerfile", metavar="<dockerfile>")
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["table", "json", "sarif", "html"], case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output", "-o", "output_path",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write output to FILE instead of stdout.",
)
@click.option(
    "--fail-on", "-F",
    default="LOW",
    show_default=True,
    metavar="SEVERITY",
    help="Exit 1 only if findings of this severity or higher are present. "
         "Choices: CRITICAL HIGH MEDIUM LOW INFO",
)
@click.option(
    "--rule", "-r",
    multiple=True,
    metavar="RULE_ID",
    help="Run only the specified rule(s), e.g. --rule DH001 --rule DH006",
)
@click.option(
    "--ignore", "-i",
    multiple=True,
    metavar="RULE_ID",
    help="Skip the specified rule(s), e.g. --ignore DH005",
)
@click.option(
    "--no-fixable-hint",
    is_flag=True,
    default=False,
    help="Suppress the 'run --fix' hint in table output.",
)
def lint_cmd(
    dockerfile: str,
    fmt: str,
    output_path: Optional[str],
    fail_on: str,
    rule: tuple,
    ignore: tuple,
    no_fixable_hint: bool,
):
    """
    Lint <dockerfile> and report hardening findings.

    Exits 1 if any findings at or above --fail-on severity are found.
    """
    _assert_file_exists(dockerfile)
    fail_severity = _severity_from_str(fail_on)

    try:
        parsed = parse_dockerfile(dockerfile)
    except Exception as exc:
        click.echo(f"[error] Failed to parse {dockerfile}: {exc}", err=True)
        sys.exit(2)

    # Filter rules.
    active_rules = list(ALL_RULES)
    if rule:
        ids = {r.upper() for r in rule}
        active_rules = [r for r in active_rules if r.RULE_ID in ids]
    if ignore:
        ids = {i.upper() for i in ignore}
        active_rules = [r for r in active_rules if r.RULE_ID not in ids]

    results = [r.check(parsed) for r in active_rules]
    all_findings = [f for r in results for f in r.findings]

    # output
    out_stream = None
    if output_path and fmt != "html":
        out_stream = open(output_path, "w", encoding="utf-8")

    fmt_lower = fmt.lower()
    if fmt_lower == "table":
        report_table(results, dockerfile, out=out_stream)
    elif fmt_lower == "json":
        report_json(results, dockerfile, out=out_stream)
    elif fmt_lower == "sarif":
        report_sarif(results, dockerfile, out=out_stream)
    elif fmt_lower == "html":
        report_html(results, dockerfile, output_path=output_path, out=out_stream)

    if out_stream:
        out_stream.close()
        click.echo(f"Report written to: {output_path}", err=True)

    #  exit code
    _sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    threshold_idx = _sev_order.index(fail_severity)

    should_fail = any(
        _sev_order.index(f.severity) >= threshold_idx
        for f in all_findings
    )
    sys.exit(1 if should_fail else 0)

#  fix

@main.command("fix")
@click.argument("dockerfile", default="Dockerfile", metavar="<dockerfile>")
@click.option(
    "--dry-run", "-n",
    is_flag=True,
    default=False,
    help="Show what would be changed without writing to disk.",
)
@click.option(
    "--no-backup",
    is_flag=True,
    default=False,
    help="Do not write a .bak file before modifying the Dockerfile.",
)
@click.option(
    "--rule", "-r",
    multiple=True,
    metavar="RULE_ID",
    help="Fix only the specified rule(s).",
)
def fix_cmd(dockerfile: str, dry_run: bool, no_backup: bool, rule: tuple):
    """
    Auto-apply fixable findings to <dockerfile>.

    A .bak backup is created by default. Use --dry-run to preview changes.
    """
    _assert_file_exists(dockerfile)

    try:
        parsed = parse_dockerfile(dockerfile)
    except Exception as exc:
        click.echo(f"[error] Failed to parse {dockerfile}: {exc}", err=True)
        sys.exit(2)

    active_rules = list(ALL_RULES)
    if rule:
        ids = {r.upper() for r in rule}
        active_rules = [r for r in active_rules if r.RULE_ID in ids]

    results = [r.check(parsed) for r in active_rules]
    all_findings = [f for r in results for f in r.findings]
    fixable = [f for f in all_findings if f.fixable]

    if not fixable:
        click.echo("No auto-fixable findings found.")
        sys.exit(0)

    click.echo(f"Found {len(fixable)} auto-fixable finding(s).")

    fixer = Fixer(dockerfile, dry_run=dry_run, backup=not no_backup)
    applied = fixer.apply(fixable)

    if not applied:
        click.echo("No changes made (findings may already be resolved).")
        sys.exit(0)

    action = "Would apply" if dry_run else "Applied"
    click.echo(f"\n{action} {len(applied)} fix(es):\n")
    for fix in applied:
        click.echo(f"  [{fix.rule_id}] Line {fix.line_number}: {fix.description}")
        if dry_run:
            click.echo(f"    Before: {fix.before}")
            click.echo(f"    After:  {fix.after}")

    if dry_run:
        click.echo("\n[dry-run] No files were modified.")
    else:
        if not no_backup:
            click.echo(f"\nBackup saved to: {dockerfile}.bak")
        click.echo(f"Wrote: {dockerfile}")

#  rules

@main.command("rules")
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["table", "json"], case_sensitive=False),
    default="table",
    help="Output format.",
)
def rules_cmd(fmt: str):
    """List all available hardening rules."""
    if fmt == "json":
        data = [
            {
                "rule_id": r.RULE_ID,
                "name": r.NAME,
                "severity": r.SEVERITY.value,
                "description": r.DESCRIPTION,
                "tags": r.TAGS,
            }
            for r in ALL_RULES
        ]
        import json
        click.echo(json.dumps(data, indent=2))
        return

    from rich import box
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(
        title="Available Rules",
        box=box.ROUNDED,
        header_style="bold white on dark_blue",
    )
    table.add_column("ID", style="cyan bold", width=8)
    table.add_column("Name", width=20)
    table.add_column("Severity", width=10)
    table.add_column("Description", ratio=1)
    table.add_column("Tags", width=30)

    for r in ALL_RULES:
        table.add_row(
            r.RULE_ID,
            r.NAME,
            f"[{r.SEVERITY.colour}]{r.SEVERITY.value}[/{r.SEVERITY.colour}]",
            r.DESCRIPTION,
            ", ".join(r.TAGS),
        )

    console.print(table)

#  utils

def _assert_file_exists(path: str):
    if not Path(path).exists():
        click.echo(f"[error] File not found: {path}", err=True)
        sys.exit(2)


if __name__ == "__main__":
    main()
