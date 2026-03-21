"""
Reporter module.

Generates output in four formats:
  - table  : Rich terminal table (default)
  - json   : Machine-readable JSON
  - sarif  : SARIF 2.1.0 (plugs into GitHub Code Scanning)
  - html   : Self-contained HTML dashboard
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Dict, List, Optional

from dockerfile_hardener import __version__
from dockerfile_hardener.rules.base import Finding, RuleResult, Severity

# scoring

def compute_score(findings: List[Finding]) -> int:
    """Return an integer score 0–100; higher is better."""
    deductions = sum(f.severity.score_deduction for f in findings)
    return max(0, 100 - deductions)

def score_grade(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 75:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 40:
        return "D"
    return "F"

def score_colour(score: int) -> str:
    """Rich colour name for the score."""
    if score >= 90:
        return "bold green"
    elif score >= 75:
        return "green"
    elif score >= 60:
        return "yellow"
    elif score >= 40:
        return "red"
    return "bold red"

# table reporter

def report_table(
    results: List[RuleResult],
    dockerfile_path: str,
    out: IO = None,
) -> int:
    """
    Print a Rich terminal table. Returns exit code (0 = pass, 1 = findings).
    """
    # Import Rich here so the rest of the module works without it.
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console(file=out or sys.stdout, highlight=False)
    all_findings: List[Finding] = [f for r in results for f in r.findings]

    #  header
    console.print()
    console.print(
        Panel(
            f"[bold cyan]dockerfile-hardener[/bold cyan] v{__version__}  "
            f"[dim]→[/dim]  [white]{dockerfile_path}[/white]",
            expand=False,
        )
    )

    if not all_findings:
        console.print("\n[bold green]✔ No issues found. Dockerfile looks good![/bold green]\n")
        return 0
    
    #  severity counts
    counts: Dict[Severity, int] = {s: 0 for s in Severity}
    for f in all_findings:
        counts[f.severity] += 1

    score = compute_score(all_findings)
    grade = score_grade(score)
    sc = score_colour(score)

    console.print(
        f"\n  Score: [{sc}]{score}/100 ({grade})[/{sc}]   "
        + "  ".join(
            f"[{sev.colour}]{sev.emoji} {sev.value}: {counts[sev]}[/{sev.colour}]"
            for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
            if counts[sev]
        )
    )
    console.print()

    # findings table
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on dark_blue",
        expand=True,
    )
    table.add_column("Line", style="dim", width=5, justify="right")
    table.add_column("Rule", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Message", ratio=3)
    table.add_column("Fix", ratio=2)
    table.add_column("Auto", width=5, justify="center")

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        sev_findings = [f for f in all_findings if f.severity == sev]
        for f in sev_findings:
            line_str = str(f.line_number) if f.line_number else "—"
            sev_text = Text(f"{f.severity.emoji} {f.severity.value}", style=f.severity.colour)
            auto_text = Text("✔", style="green") if f.fixable else Text("✗", style="dim")
            table.add_row(
                line_str,
                f"[bold]{f.rule_id}[/bold]\n[dim]{f.rule_name}[/dim]",
                sev_text,
                f.message,
                f.fix_description or "—",
                auto_text,
            )

    console.print(table)
    console.print(
        "\n[dim]Run with [bold]--fix[/bold] to auto-apply fixable findings. "
        "Use [bold]--format html[/bold] for a full report.[/dim]\n"
    )

    return 1 if all_findings else 0

# JSON reporter

def report_json(
    results: List[RuleResult],
    dockerfile_path: str,
    out: IO = None,
) -> int:
    all_findings = [f for r in results for f in r.findings]
    score = compute_score(all_findings)

    data = {
        "tool": "dockerfile-hardener",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dockerfile": dockerfile_path,
        "score": score,
        "grade": score_grade(score),
        "summary": {
            sev.value: sum(1 for f in all_findings if f.severity == sev)
            for sev in Severity
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "line_number": f.line_number,
                "message": f.message,
                "fix_description": f.fix_description,
                "fixable": f.fixable,
                "context": f.context,
                "stage_index": f.stage_index,
                "tags": f.tags,
            }
            for f in all_findings
        ],
    }

    stream = out or sys.stdout
    json.dump(data, stream, indent=2)
    stream.write("\n")
    return 1 if all_findings else 0


# - SARIF reporter


def report_sarif(
    results: List[RuleResult],
    dockerfile_path: str,
    out: IO = None,
) -> int:
    """
    Emit SARIF 2.1.0 — compatible with GitHub Code Scanning (upload-sarif action).
    """
    all_findings = [f for r in results for f in r.findings]

    _SARIF_LEVEL = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }

    # Build unique rules list.
    seen_rule_ids: set = set()
    sarif_rules = []
    for r in results:
        if r.rule_id not in seen_rule_ids:
            seen_rule_ids.add(r.rule_id)
            sarif_rules.append(
                {
                    "id": r.rule_id,
                    "name": r.rule_name,
                    "shortDescription": {"text": r.rule_name},
                    "helpUri": (
                        f"https://github.com/macbuildssys/dockerfile-hardener"
                        f"/blob/main/docs/rules/{r.rule_id}.md"
                    ),
                }
            )

    sarif = {
        "version": "2.1.0",
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dockerfile-hardener",
                        "version": __version__,
                        "informationUri": "https://github.com/macbuildssys/dockerfile-hardener",
                        "rules": sarif_rules,
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": _SARIF_LEVEL[f.severity],
                        "message": {"text": f.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": dockerfile_path},
                                    "region": {
                                        "startLine": f.line_number or 1,
                                    },
                                }
                            }
                        ],
                    }
                    for f in all_findings
                ],
            }
        ],
    }

    stream = out or sys.stdout
    json.dump(sarif, stream, indent=2)
    stream.write("\n")
    return 1 if all_findings else 0

# HTML reporter

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>dockerfile-hardener report – {dockerfile}</title>
<style>
  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --critical: #f85149;
    --high: #ff7b72;
    --medium: #e3b341;
    --low: #58a6ff;
    --info: #8b949e;
    --green: #3fb950;
    --score-a: #3fb950;
    --score-b: #56d364;
    --score-c: #e3b341;
    --score-d: #f0883e;
    --score-f: #f85149;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    font-size: 14px;
    line-height: 1.6;
    padding: 24px;
  }}
  .header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 24px;
  }}
  .header h1 {{ font-size: 20px; color: var(--text); }}
  .header .meta {{ color: var(--muted); font-size: 12px; }}
  .score-badge {{
    display: flex;
    flex-direction: column;
    align-items: center;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 24px;
  }}
  .score-badge .score {{ font-size: 36px; font-weight: 700; }}
  .score-badge .label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }}
  .score-a {{ color: var(--score-a); }}
  .score-b {{ color: var(--score-b); }}
  .score-c {{ color: var(--score-c); }}
  .score-d {{ color: var(--score-d); }}
  .score-f {{ color: var(--score-f); }}
  .cards {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 24px;
  }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px 20px;
    min-width: 120px;
    text-align: center;
  }}
  .card .count {{ font-size: 28px; font-weight: 700; }}
  .card .sev {{ font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); margin-top: 4px; }}
  .critical {{ color: var(--critical); }}
  .high     {{ color: var(--high); }}
  .medium   {{ color: var(--medium); }}
  .low      {{ color: var(--low); }}
  .info     {{ color: var(--info); }}
  table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--surface);
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid var(--border);
  }}
  thead tr {{
    background: #1c2128;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  th, td {{
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .badge.critical {{ background: rgba(248,81,73,0.15); color: var(--critical); border: 1px solid var(--critical); }}
  .badge.high     {{ background: rgba(255,123,114,0.15); color: var(--high); border: 1px solid var(--high); }}
  .badge.medium   {{ background: rgba(227,179,65,0.15); color: var(--medium); border: 1px solid var(--medium); }}
  .badge.low      {{ background: rgba(88,166,255,0.15); color: var(--low); border: 1px solid var(--low); }}
  .badge.info     {{ background: rgba(139,148,158,0.15); color: var(--info); border: 1px solid var(--info); }}
  .fix-badge {{
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 10px;
    background: rgba(63,185,80,0.15);
    color: var(--green);
    border: 1px solid var(--green);
  }}
  .line {{ color: var(--muted); font-size: 12px; font-family: monospace; }}
  .context {{ font-family: monospace; font-size: 12px; color: var(--muted); margin-top: 4px;
              background: rgba(0,0,0,0.3); padding: 4px 8px; border-radius: 4px; word-break: break-all; }}
  .rule-id {{ font-family: monospace; font-size: 12px; color: var(--low); font-weight: 600; }}
  .fix-desc {{ font-size: 12px; color: var(--muted); margin-top: 4px; }}
  .pass-banner {{
    text-align: center;
    padding: 48px;
    color: var(--green);
    font-size: 20px;
    font-weight: 600;
  }}
  .footer {{ margin-top: 32px; text-align: center; color: var(--muted); font-size: 11px; }}
  .section-title {{
    font-size: 13px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 12px;
    margin-top: 24px;
  }}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>🐳 dockerfile-hardener</h1>
    <div class="meta">{dockerfile} &nbsp;·&nbsp; {timestamp} &nbsp;·&nbsp; v{version}</div>
  </div>
  <div class="score-badge">
    <div class="score {score_cls}">{score}/100</div>
    <div class="label">Grade {grade}</div>
  </div>
</div>

{pass_or_cards}

{findings_section}

<div class="footer">Generated by
  <a href="https://github.com/macbuildssys/dockerfile-hardener" style="color:var(--low)">
    dockerfile-hardener
  </a> v{version}
</div>
</body>
</html>
"""


def report_html(
    results: List[RuleResult],
    dockerfile_path: str,
    output_path: Optional[str] = None,
    out: IO = None,
) -> int:
    all_findings = [f for r in results for f in r.findings]
    score = compute_score(all_findings)
    grade = score_grade(score)
    score_cls = f"score-{grade.lower()}"

    # cards
    if not all_findings:
        pass_or_cards = (
            '<div class="pass-banner">✔ No issues found — Dockerfile passes all checks.</div>'
        )
        findings_section = ""
    else:
        counts = {s: sum(1 for f in all_findings if f.severity == s) for s in Severity}
        cards_html = '<div class="cards">\n'
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if counts[sev]:
                cards_html += (
                    f'  <div class="card">'
                    f'<div class="count {sev.html_class}">{counts[sev]}</div>'
                    f'<div class="sev {sev.html_class}">{sev.value}</div>'
                    f'</div>\n'
                )
        cards_html += "</div>"
        pass_or_cards = cards_html

        #  table
        rows = ""
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            for f in all_findings:
                if f.severity != sev:
                    continue
                line_str = str(f.line_number) if f.line_number else "—"
                ctx_html = (
                    f'<div class="context">{_escape(f.context)}</div>' if f.context else ""
                )
                fix_html = (
                    f'<div class="fix-desc">{_escape(f.fix_description)}</div>'
                    if f.fix_description
                    else ""
                )
                auto_html = (
                    '<span class="fix-badge">auto-fix</span>' if f.fixable else ""
                )
                rows += (
                    f"<tr>"
                    f"<td><span class='line'>{line_str}</span></td>"
                    f"<td><span class='rule-id'>{f.rule_id}</span><br>"
                    f"<span style='color:var(--muted);font-size:11px'>{f.rule_name}</span></td>"
                    f"<td><span class='badge {f.severity.html_class}'>{f.severity.value}</span></td>"
                    f"<td>{_escape(f.message)}{ctx_html}</td>"
                    f"<td>{fix_html}{auto_html}</td>"
                    f"</tr>\n"
                )

        findings_section = f"""
<div class="section-title">Findings ({len(all_findings)})</div>
<table>
  <thead>
    <tr>
      <th>Line</th>
      <th>Rule</th>
      <th>Severity</th>
      <th>Message</th>
      <th>Recommended Fix</th>
    </tr>
  </thead>
  <tbody>
{rows}  </tbody>
</table>"""

    html = _HTML_TEMPLATE.format(
        dockerfile=_escape(dockerfile_path),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        version=__version__,
        score=score,
        grade=grade,
        score_cls=score_cls,
        pass_or_cards=pass_or_cards,
        findings_section=findings_section,
    )

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")
    elif out:
        out.write(html)
    else:
        sys.stdout.write(html)

    return 1 if all_findings else 0


def _escape(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
