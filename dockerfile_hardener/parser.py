"""
Dockerfile parser.

Converts raw Dockerfile text into a list of structured Instruction objects,
handling line continuations, multi-stage builds, and comment stripping.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class Instruction:
    """Represents a single logical Dockerfile instruction."""

    command: str  # Uppercased keyword: FROM, RUN, ENV, COPY, etc.
    value: str  # Everything after the keyword (stripped)
    line_number: int  # 1-indexed line of the instruction's start
    stage_index: int  # 0-indexed stage (increments at each FROM)
    stage_name: Optional[str]  # AS <name> value from FROM, or None
    is_last_stage: bool = False  # True if this instruction belongs to the final stage
    raw_value: str = ""  # Unmodified value before continuation join


@dataclass
class ParsedDockerfile:
    """Holds all instructions parsed from a Dockerfile."""

    path: str
    instructions: List[Instruction]
    raw_lines: List[str]
    stage_count: int = 0

    # ------------------------------------------------------------------ helpers

    def by_command(self, command: str) -> List[Instruction]:
        """Return all instructions matching `command` (case-insensitive)."""
        return [i for i in self.instructions if i.command == command.upper()]

    def in_stage(self, stage_index: int) -> List[Instruction]:
        """Return all instructions in the given stage."""
        return [i for i in self.instructions if i.stage_index == stage_index]

    def in_last_stage(self) -> List[Instruction]:
        """Return all instructions in the final build stage."""
        return self.in_stage(self.stage_count - 1)

    def has_command(self, command: str) -> bool:
        return bool(self.by_command(command))

    def has_command_in_stage(self, command: str, stage_index: int) -> bool:
        return any(
            i.command == command.upper() for i in self.instructions if i.stage_index == stage_index
        )

    def stage_names(self) -> List[Optional[str]]:
        """Return one entry per stage: the AS name or None."""
        names: List[Optional[str]] = []
        for instr in self.instructions:
            if instr.command == "FROM":
                if instr.stage_index >= len(names):
                    names.append(instr.stage_name)
        return names


# --------------------------------------------------------------------------- parser


def parse_dockerfile(path: str) -> ParsedDockerfile:
    """
    Parse the Dockerfile at *path* and return a ParsedDockerfile.

    Handles:
    - Line continuations (trailing backslash)
    - Inline and standalone comments
    - Multi-stage builds (multiple FROM instructions)
    - Heredoc syntax (best-effort; the block is kept as-is in value)
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Dockerfile not found: {path}")

    raw_text = p.read_text(encoding="utf-8", errors="replace")
    raw_lines = raw_text.splitlines()

    instructions: List[Instruction] = []
    stage_index = -1
    current_stage_name: Optional[str] = None

    i = 0
    while i < len(raw_lines):
        stripped = raw_lines[i].strip()

        # Skip blank lines and comment-only lines.
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Record the starting line number of this logical instruction.
        line_number = i + 1  # 1-indexed

        # Collect logical line by joining continuations.
        logical_parts: List[str] = []
        in_heredoc = False

        while i < len(raw_lines):
            current = raw_lines[i]
            stripped_current = current.strip()

            # Strip inline comments (but not inside quoted strings — best-effort).
            # Only strip if '#' is preceded by whitespace (not inside a value).
            comment_match = re.search(r'\s#[^"\']*$', stripped_current)
            if comment_match:
                stripped_current = stripped_current[: comment_match.start()].strip()

            if stripped_current.endswith("\\") and not in_heredoc:
                logical_parts.append(stripped_current[:-1].strip())
                i += 1
            else:
                logical_parts.append(stripped_current)
                i += 1
                break

        logical_line = " ".join(p for p in logical_parts if p)

        if not logical_line:
            continue

        # Split into command and value.
        tokens = logical_line.split(None, 1)
        command = tokens[0].upper()
        value = tokens[1].strip() if len(tokens) > 1 else ""

        # Track stage transitions.
        if command == "FROM":
            stage_index += 1
            # Extract AS <name>: "image:tag AS stagename"
            as_match = re.search(r"\bAS\s+(\S+)\s*$", value, re.IGNORECASE)
            current_stage_name = as_match.group(1) if as_match else None

        if stage_index < 0:
            # Instruction before any FROM — treat as stage 0 (unusual but handle it).
            stage_index = 0

        instr = Instruction(
            command=command,
            value=value,
            line_number=line_number,
            stage_index=stage_index,
            stage_name=current_stage_name,
            raw_value=value,
        )
        instructions.append(instr)

    stage_count = stage_index + 1 if stage_index >= 0 else 0

    # Mark instructions that belong to the last stage.
    last = stage_count - 1
    for instr in instructions:
        instr.is_last_stage = instr.stage_index == last

    return ParsedDockerfile(
        path=str(path),
        instructions=instructions,
        raw_lines=raw_lines,
        stage_count=stage_count,
    )
