"""
Shared pytest fixtures for dockerfile-hardener tests.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Callable

import pytest

from dockerfile_hardener.parser import ParsedDockerfile, parse_dockerfile

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_path():
    """Return the path to a named fixture Dockerfile."""

    def _path(name: str) -> str:
        return str(FIXTURES_DIR / name)

    return _path


@pytest.fixture
def parse_inline(tmp_path) -> Callable[[str], ParsedDockerfile]:
    """
    Parse an inline Dockerfile string.

    Usage:
        df = parse_inline(\"\"\"
            FROM ubuntu:22.04
            RUN echo hello
        \"\"\")
    """
    counter = [0]

    def _parse(content: str) -> ParsedDockerfile:
        counter[0] += 1
        p = tmp_path / f"Dockerfile.test{counter[0]}"
        p.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
        return parse_dockerfile(str(p))

    return _parse
