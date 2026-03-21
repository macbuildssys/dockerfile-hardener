"""
Rules package.

Exports ALL_RULES — the canonical ordered list of rule instances used by
the linter. To add a new rule: implement BaseRule, import it here, and
append an instance to ALL_RULES.
"""

from .add_instruction import AddInstructionRule
from .apt_hygiene import AptHygieneRule
from .base import BaseRule, Finding, RuleResult, Severity
from .file_ownership import FileOwnershipRule
from .latest_tag import LatestTagRule
from .multistage import MultiStageRule
from .no_healthcheck import NoHealthcheckRule
from .privileged_port import PrivilegedPortRule
from .root_user import RootUserRule
from .secrets_in_env import SecretsInEnvRule
from .shell_tools import ShellToolsRule

# Ordered list: most critical rules first.
ALL_RULES: list[BaseRule] = [
    RootUserRule(),
    LatestTagRule(),
    SecretsInEnvRule(),
    ShellToolsRule(),
    MultiStageRule(),
    AptHygieneRule(),
    AddInstructionRule(),
    FileOwnershipRule(),
    PrivilegedPortRule(),
    NoHealthcheckRule(),
]

__all__ = [
    "ALL_RULES",
    "BaseRule",
    "Finding",
    "RuleResult",
    "Severity",
    "RootUserRule",
    "LatestTagRule",
    "SecretsInEnvRule",
    "ShellToolsRule",
    "MultiStageRule",
    "AptHygieneRule",
    "AddInstructionRule",
    "FileOwnershipRule",
    "PrivilegedPortRule",
    "NoHealthcheckRule",
]
