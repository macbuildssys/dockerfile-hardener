"""
Fixer module.

Reads findings flagged as fixable=True and applies them to the raw Dockerfile
text. Each fix is implemented as a targeted text transform. Fixes are applied
in reverse line-number order so that earlier line-number offsets remain valid
after each edit.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from dockerfile_hardener.rules.base import Finding, Severity


@dataclass
class AppliedFix:
    """Records a single fix that was applied."""

    rule_id: str
    rule_name: str
    line_number: Optional[int]
    description: str
    before: str
    after: str


class Fixer:
    """
    Applies auto-fixable findings to a Dockerfile in-place.

    Strategy:
      - Build a list of per-line patch functions.
      - Apply them in reverse line order to preserve offsets.
      - Each patch is idempotent when run twice.
    """

    def __init__(self, dockerfile_path: str, dry_run: bool = False, backup: bool = True):
        self.path = Path(dockerfile_path)
        self.dry_run = dry_run
        self.backup = backup

    def apply(self, findings: List[Finding]) -> List[AppliedFix]:
        """
        Apply all fixable findings.  Returns a list of AppliedFix records.
        """
        lines = self.path.read_text(encoding="utf-8").splitlines(keepends=True)
        applied: List[AppliedFix] = []

        # Sort fixable findings in reverse line order.
        fixable = sorted(
            [f for f in findings if f.fixable],
            key=lambda f: f.line_number or 0,
            reverse=True,
        )

        for finding in fixable:
            patch_fn = _get_patch(finding.rule_id)
            if patch_fn is None:
                continue
            result = patch_fn(lines, finding)
            if result:
                applied.append(result)

        if not self.dry_run and applied:
            if self.backup:
                shutil.copy2(self.path, str(self.path) + ".bak")
            self.path.write_text("".join(lines), encoding="utf-8")

        return applied


# patch registry

_PATCH_REGISTRY: dict[str, callable] = {}


def _register(rule_id: str):
    """Decorator to register a patch function for a rule."""

    def decorator(fn):
        _PATCH_REGISTRY[rule_id] = fn
        return fn

    return decorator


def _get_patch(rule_id: str):
    return _PATCH_REGISTRY.get(rule_id)


# DH001: RootUser


@_register("DH001")
def _fix_root_user(lines: List[str], finding: Finding) -> Optional[AppliedFix]:
    """
    Append `USER nonroot` before the last CMD or ENTRYPOINT in the final stage.
    If no CMD/ENTRYPOINT exists, append to the end of the file.
    """
    # Find the last CMD or ENTRYPOINT line (1-indexed → 0-indexed).
    target_idx = None
    for idx in range(len(lines) - 1, -1, -1):
        line = lines[idx]
        # Only match top-level CMD/ENTRYPOINT — Dockerfile instructions never have
        # leading whitespace.  Indented "CMD ..." inside a HEALTHCHECK must be skipped.
        if line and line[0] not in (" ", "\t"):
            stripped = line.strip().upper()
            if stripped.startswith("CMD") or stripped.startswith("ENTRYPOINT"):
                target_idx = idx
                break

    insert_line = "USER nonroot\n"

    if target_idx is not None:
        # Check if USER nonroot is already present just before this line.
        prev = lines[target_idx - 1].strip().lower() if target_idx > 0 else ""
        if "user" in prev and "nonroot" in prev:
            return None  # Already fixed.

        before = lines[target_idx]
        lines.insert(target_idx, insert_line)
        return AppliedFix(
            rule_id="DH001",
            rule_name="RootUser",
            line_number=target_idx + 1,
            description='Inserted "USER nonroot" before CMD/ENTRYPOINT.',
            before=before,
            after=insert_line + before,
        )
    else:
        # No CMD/ENTRYPOINT — append to end.
        before = ""
        lines.append(insert_line)
        return AppliedFix(
            rule_id="DH001",
            rule_name="RootUser",
            line_number=len(lines),
            description='Appended "USER nonroot" to end of Dockerfile.',
            before=before,
            after=insert_line,
        )


#  DH005: NoHealthcheck


@_register("DH005")
def _fix_no_healthcheck(lines: List[str], finding: Finding) -> Optional[AppliedFix]:
    """
    Append a HEALTHCHECK template before the last CMD/ENTRYPOINT, or at EOF.
    """
    # Don't add if one already exists.
    for line in lines:
        if line.strip().upper().startswith("HEALTHCHECK"):
            return None

    healthcheck = (
        "HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \\\n"
        "    CMD wget -qO- http://localhost:8080/health || exit 1\n"
    )

    target_idx = None
    for idx in range(len(lines) - 1, -1, -1):
        line = lines[idx]
        if line and line[0] not in (" ", "\t"):
            stripped = line.strip().upper()
            if stripped.startswith("CMD") or stripped.startswith("ENTRYPOINT"):
                target_idx = idx
                break

    if target_idx is not None:
        before = lines[target_idx]
        lines.insert(target_idx, healthcheck)
        return AppliedFix(
            rule_id="DH005",
            rule_name="NoHealthcheck",
            line_number=target_idx + 1,
            description="Inserted HEALTHCHECK template before CMD/ENTRYPOINT.",
            before=before,
            after=healthcheck + before,
        )
    else:
        lines.append(healthcheck)
        return AppliedFix(
            rule_id="DH005",
            rule_name="NoHealthcheck",
            line_number=len(lines),
            description="Appended HEALTHCHECK template to end of Dockerfile.",
            before="",
            after=healthcheck,
        )


# DH007: AddInstruction (local file ADD to COPY)


@_register("DH007")
def _fix_add_instruction(lines: List[str], finding: Finding) -> Optional[AppliedFix]:
    """
    Replace `ADD <local> <dest>` with `COPY <local> <dest>` when the source
    is a local file (not a URL, not a tar archive with deliberate extraction).
    Only fixes INFO/MEDIUM severity ADD findings (local copy cases).
    """
    if finding.severity not in (Severity.MEDIUM, Severity.INFO):
        return None

    line_idx = (finding.line_number or 1) - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    original = lines[line_idx]
    # Replace the ADD keyword at the start of the instruction (may have leading whitespace).
    fixed = re.sub(r"^(\s*)ADD\b", r"\1COPY", original, count=1, flags=re.IGNORECASE)

    if fixed == original:
        return None

    lines[line_idx] = fixed
    return AppliedFix(
        rule_id="DH007",
        rule_name="AddInstruction",
        line_number=finding.line_number,
        description="Replaced ADD with COPY.",
        before=original.rstrip(),
        after=fixed.rstrip(),
    )


#  DH008: AptHygiene — cache cleanup + --no-install-recommends


@_register("DH008")
def _fix_apt_hygiene(lines: List[str], finding: Finding) -> Optional[AppliedFix]:
    """
    For apt-get install lines:
      - Append '&& rm -rf /var/lib/apt/lists/*' if cache is not cleaned.
      - Append '--no-install-recommends' if missing.

    Handles multi-line RUN instructions by finding the last continuation line.
    """
    line_idx = (finding.line_number or 1) - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    # Find the end of the RUN instruction (may span multiple lines via `\`).
    end_idx = line_idx
    while end_idx < len(lines) - 1 and lines[end_idx].rstrip().endswith("\\"):
        end_idx += 1

    original_end = lines[end_idx]
    modified_end = original_end

    # Fix 1: Add --no-install-recommends.
    if (
        "no-install-recommends" not in finding.message.lower()
        and "cache" not in finding.message.lower()
    ):
        return None  # Not a hygiene we handle here.

    if "no-install-recommends" in finding.message:
        install_re = re.compile(r"(apt-get\s+install)", re.IGNORECASE)
        modified_end = install_re.sub(r"\1 --no-install-recommends", modified_end, count=1)

    # Fix 2: Append cache cleanup.
    if "cache" in finding.message or "lists" in finding.message:
        end_stripped = modified_end.rstrip()
        if not end_stripped.endswith("\\"):
            modified_end = end_stripped + " \\\n    && rm -rf /var/lib/apt/lists/*\n"
        else:
            modified_end = end_stripped + "\n    && rm -rf /var/lib/apt/lists/*\n"

    if modified_end == original_end:
        return None

    lines[end_idx] = modified_end
    return AppliedFix(
        rule_id="DH008",
        rule_name="AptHygiene",
        line_number=finding.line_number,
        description="Applied apt-get hygiene fix.",
        before=original_end.rstrip(),
        after=modified_end.rstrip(),
    )


#  DH010: FileOwnership


@_register("DH010")
def _fix_file_ownership(lines: List[str], finding: Finding) -> Optional[AppliedFix]:
    """
    Add --chown=nonroot:nonroot to COPY/ADD instructions that are missing it.
    Extracts the actual user from the finding's fix_description.
    """
    line_idx = (finding.line_number or 1) - 1
    if line_idx < 0 or line_idx >= len(lines):
        return None

    original = lines[line_idx]

    # Extract user from fix_description: "--chown=<user>:<group>"
    chown_re = re.compile(r"--chown=(\S+:\S+)")
    fd_match = chown_re.search(finding.fix_description or "")
    chown_value = fd_match.group(1) if fd_match else "nonroot:nonroot"

    # Don't double-apply.
    if "--chown" in original:
        return None

    # Insert --chown after COPY or ADD keyword.
    fixed = re.sub(
        r"^(\s*(?:COPY|ADD)\b)",
        rf"\1 --chown={chown_value}",
        original,
        count=1,
        flags=re.IGNORECASE,
    )

    if fixed == original:
        return None

    lines[line_idx] = fixed
    return AppliedFix(
        rule_id="DH010",
        rule_name="FileOwnership",
        line_number=finding.line_number,
        description=f"Added --chown={chown_value} to COPY/ADD instruction.",
        before=original.rstrip(),
        after=fixed.rstrip(),
    )
