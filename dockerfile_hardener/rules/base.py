"""
Base classes for all hardening rules.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    # Ordering for sorting / comparisons.
    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    @property
    def score_deduction(self) -> int:
        """Points deducted from 100 per occurrence of this severity."""
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }[self]

    @property
    def emoji(self) -> str:
        return {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }[self]

    @property
    def colour(self) -> str:
        """ANSI-ish label colour name for Rich."""
        return {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "white",
        }[self]

    @property
    def html_class(self) -> str:
        return self.value.lower()


@dataclass
class Finding:
    """A single violation found by a rule."""

    rule_id: str                        # e.g. "DH001"
    rule_name: str                      # e.g. "RootUser"
    severity: Severity
    message: str                        # Human-readable description
    line_number: Optional[int]          # Line in the Dockerfile (1-indexed), or None
    fix_description: Optional[str]      # Short description of the recommended fix
    fixable: bool = False               # Whether --fix can auto-apply the fix
    context: str = ""                   # The raw line from the Dockerfile for display
    stage_index: Optional[int] = None   # Which stage the finding belongs to
    tags: List[str] = field(default_factory=list)  # e.g. ["CIS", "OWASP"]


@dataclass
class RuleResult:
    """Aggregated output from a single rule check."""

    rule_id: str
    rule_name: str
    findings: List[Finding] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    @property
    def passed(self) -> bool:
        return not self.findings

    @property
    def finding_count(self) -> int:
        return len(self.findings)


class BaseRule(ABC):
    """
    Abstract base class for all Dockerfile hardening rules.

    Subclasses must define:
        RULE_ID   - short unique identifier, e.g. "DH001"
        NAME      - human-readable rule name
        SEVERITY  - default severity level
        TAGS      - compliance tags
        DESCRIPTION - one-line description shown in --rules list
    """

    RULE_ID: str = ""
    NAME: str = ""
    SEVERITY: Severity = Severity.MEDIUM
    TAGS: List[str] = []
    DESCRIPTION: str = ""

    @abstractmethod
    def check(self, dockerfile) -> RuleResult:
        """
        Run the rule against a ParsedDockerfile.
        Returns a RuleResult with zero or more Findings.
        """

    def _make_result(self, findings: Optional[List[Finding]] = None) -> RuleResult:
        return RuleResult(
            rule_id=self.RULE_ID,
            rule_name=self.NAME,
            findings=findings or [],
        )

    def _finding(
        self,
        message: str,
        line_number: Optional[int] = None,
        fix_description: Optional[str] = None,
        fixable: bool = False,
        context: str = "",
        stage_index: Optional[int] = None,
    ) -> Finding:
        return Finding(
            rule_id=self.RULE_ID,
            rule_name=self.NAME,
            severity=self.SEVERITY,
            message=message,
            line_number=line_number,
            fix_description=fix_description,
            fixable=fixable,
            context=context,
            stage_index=stage_index,
            tags=list(self.TAGS),
        )
