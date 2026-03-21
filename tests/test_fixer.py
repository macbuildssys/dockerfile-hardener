"""
Tests for dockerfile_hardener.fixer
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from dockerfile_hardener.fixer import Fixer
from dockerfile_hardener.parser import parse_dockerfile
from dockerfile_hardener.rules import ALL_RULES
from dockerfile_hardener.rules.base import Severity


def _all_findings(path: str):
    df = parse_dockerfile(path)
    return [f for r in ALL_RULES for f in r.check(df).findings]


# ---------------------------------------------------------------------------- DH001 RootUser fix


def test_fix_adds_user_nonroot(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM ubuntu:22.04\nCMD [\"bash\"]\n")
    findings = _all_findings(str(p))
    fixer = Fixer(str(p), backup=False)
    applied = fixer.apply(findings)
    assert any(a.rule_id == "DH001" for a in applied)
    content = p.read_text()
    assert "USER nonroot" in content


def test_fix_user_nonroot_before_cmd(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM ubuntu:22.04\nCMD [\"bash\"]\n")
    findings = _all_findings(str(p))
    Fixer(str(p), backup=False).apply(findings)
    lines = p.read_text().splitlines()
    user_idx = next(i for i, l in enumerate(lines) if "USER nonroot" in l)
    # Match only unindented CMD instructions (not CMD inside a HEALTHCHECK template).
    cmd_idx = next(
        i for i, l in enumerate(lines)
        if l and l[0] not in (" ", "\t") and l.strip().startswith("CMD")
    )
    assert user_idx < cmd_idx


# ---------------------------------------------------------------------------- DH005 NoHealthcheck fix


def test_fix_adds_healthcheck(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM ubuntu:22.04\nUSER nonroot\nCMD [\"bash\"]\n")
    findings = _all_findings(str(p))
    Fixer(str(p), backup=False).apply(findings)
    content = p.read_text()
    assert "HEALTHCHECK" in content


def test_fix_healthcheck_not_added_twice(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text(
        "FROM ubuntu:22.04\n"
        "HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n"
        "USER nonroot\n"
        "CMD [\"bash\"]\n"
    )
    findings = _all_findings(str(p))
    applied = Fixer(str(p), backup=False).apply(findings)
    hc_applied = [a for a in applied if a.rule_id == "DH005"]
    assert not hc_applied  # Should not apply again.


# ---------------------------------------------------------------------------- DH007 AddInstruction fix


def test_fix_add_to_copy(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM alpine:3.19\nADD app.py /app/app.py\nCMD [\"x\"]\n")
    findings = _all_findings(str(p))
    Fixer(str(p), backup=False).apply(findings)
    content = p.read_text()
    assert "COPY app.py" in content
    assert "ADD app.py" not in content


# ---------------------------------------------------------------------------- DH010 FileOwnership fix


def test_fix_adds_chown_to_copy(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text(
        "FROM alpine:3.19\n"
        "RUN adduser -D appuser\n"
        "USER appuser\n"
        "COPY app.py /app/app.py\n"
        "CMD [\"x\"]\n"
    )
    findings = _all_findings(str(p))
    Fixer(str(p), backup=False).apply(findings)
    content = p.read_text()
    assert "--chown=" in content


# ---------------------------------------------------------------------------- dry-run


def test_dry_run_does_not_modify_file(tmp_path):
    p = tmp_path / "Dockerfile"
    original = "FROM ubuntu:22.04\nCMD [\"bash\"]\n"
    p.write_text(original)
    findings = _all_findings(str(p))
    Fixer(str(p), dry_run=True, backup=False).apply(findings)
    assert p.read_text() == original


def test_dry_run_returns_applied_list(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM ubuntu:22.04\nCMD [\"bash\"]\n")
    findings = _all_findings(str(p))
    applied = Fixer(str(p), dry_run=True, backup=False).apply(findings)
    assert applied  # Should describe what would be applied.


# ---------------------------------------------------------------------------- backup


def test_backup_created_by_default(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM ubuntu:22.04\nCMD [\"bash\"]\n")
    findings = _all_findings(str(p))
    Fixer(str(p), backup=True).apply(findings)
    bak = Path(str(p) + ".bak")
    assert bak.exists()
    assert bak.read_text() == "FROM ubuntu:22.04\nCMD [\"bash\"]\n"


def test_no_backup_when_disabled(tmp_path):
    p = tmp_path / "Dockerfile"
    p.write_text("FROM ubuntu:22.04\nCMD [\"bash\"]\n")
    findings = _all_findings(str(p))
    Fixer(str(p), backup=False).apply(findings)
    bak = Path(str(p) + ".bak")
    assert not bak.exists()
