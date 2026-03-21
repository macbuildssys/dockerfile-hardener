"""
Tests for all 10 dockerfile-hardener rules.
"""

from __future__ import annotations

from dockerfile_hardener.rules import (
    AddInstructionRule,
    AptHygieneRule,
    FileOwnershipRule,
    LatestTagRule,
    MultiStageRule,
    NoHealthcheckRule,
    PrivilegedPortRule,
    RootUserRule,
    SecretsInEnvRule,
    ShellToolsRule,
)
from dockerfile_hardener.rules.base import Severity

# ============================================================================ DH001 RootUser


class TestRootUserRule:
    rule = RootUserRule()

    def test_flags_missing_user(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nCMD ['bash']")
        result = self.rule.check(df)
        assert not result.passed
        assert any("no USER" in f.message or "no user" in f.message.lower() for f in result.findings)

    def test_flags_explicit_root(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nUSER root\nCMD ['bash']")
        result = self.rule.check(df)
        assert not result.passed

    def test_flags_uid_zero(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nUSER 0\nCMD ['bash']")
        result = self.rule.check(df)
        assert not result.passed

    def test_passes_with_nonroot_user(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nUSER nonroot\nCMD ['bash']")
        result = self.rule.check(df)
        assert result.passed

    def test_passes_with_numeric_nonroot(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nUSER 65532\nCMD ['bash']")
        result = self.rule.check(df)
        assert result.passed

    def test_only_flags_final_stage(self, parse_inline):
        # Build stage has no USER — should NOT trigger (build stages can run as root).
        df = parse_inline("""
            FROM golang:1.22 AS builder
            RUN go build .

            FROM gcr.io/distroless/static:nonroot
            COPY --from=builder /app /app
            USER nonroot
            CMD ["/app"]
        """)
        result = self.rule.check(df)
        assert result.passed

    def test_finding_is_fixable(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nCMD ['bash']")
        result = self.rule.check(df)
        assert any(f.fixable for f in result.findings)

    def test_severity_is_critical(self):
        assert self.rule.SEVERITY == Severity.CRITICAL


# ============================================================================ DH002 LatestTag


class TestLatestTagRule:
    rule = LatestTagRule()

    def test_flags_latest_tag(self, parse_inline):
        df = parse_inline("FROM ubuntu:latest\nCMD ['bash']")
        result = self.rule.check(df)
        assert not result.passed

    def test_flags_missing_tag(self, parse_inline):
        df = parse_inline("FROM ubuntu\nCMD ['bash']")
        result = self.rule.check(df)
        assert not result.passed

    def test_passes_pinned_tag(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nCMD ['bash']")
        result = self.rule.check(df)
        assert result.passed

    def test_passes_digest(self, parse_inline):
        df = parse_inline(
            "FROM ubuntu@sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc123\nCMD ['x']"
        )
        result = self.rule.check(df)
        assert result.passed

    def test_passes_scratch(self, parse_inline):
        df = parse_inline("FROM scratch\nCOPY app /app\nCMD ['/app']")
        result = self.rule.check(df)
        assert result.passed

    def test_passes_build_arg(self, parse_inline):
        df = parse_inline("ARG BASE\nFROM ${BASE}\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed

    def test_flags_multiple_stages(self, parse_inline):
        df = parse_inline("""
            FROM golang:latest AS builder
            RUN go build .
            FROM alpine
            COPY --from=builder /app /app
            CMD ["/app"]
        """)
        result = self.rule.check(df)
        assert len(result.findings) == 2  # Both stages should be flagged.

    def test_severity_is_high(self):
        assert self.rule.SEVERITY == Severity.HIGH


# ============================================================================ DH003 ShellTools


class TestShellToolsRule:
    rule = ShellToolsRule()

    def test_flags_curl_in_final_stage(self, parse_inline):
        df = parse_inline("""
            FROM ubuntu:22.04
            RUN apt-get install -y curl
            CMD ['app']
        """)
        result = self.rule.check(df)
        assert not result.passed
        assert any("curl" in f.message for f in result.findings)

    def test_flags_wget_in_final_stage(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nRUN apk add wget\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_flags_bash_in_final_stage(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nRUN apk add bash\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_does_not_flag_build_stage(self, parse_inline):
        df = parse_inline("""
            FROM ubuntu:22.04 AS builder
            RUN apt-get install -y gcc make curl
            RUN make

            FROM gcr.io/distroless/static:nonroot
            COPY --from=builder /app /app
            CMD ["/app"]
        """)
        result = self.rule.check(df)
        assert result.passed

    def test_does_not_flag_non_install_run(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nRUN echo 'curl is a thing'\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed

    def test_severity_is_high(self):
        assert self.rule.SEVERITY == Severity.HIGH


# ============================================================================ DH004 MultiStage


class TestMultiStageRule:
    rule = MultiStageRule()

    def test_flags_build_tool_in_single_stage(self, parse_inline):
        df = parse_inline("""
            FROM ubuntu:22.04
            RUN apt-get install -y gcc
            CMD ['app']
        """)
        result = self.rule.check(df)
        assert not result.passed

    def test_flags_go_build_in_single_stage(self, parse_inline):
        df = parse_inline("FROM golang:1.22\nRUN go build .\nCMD ['./app']")
        result = self.rule.check(df)
        assert not result.passed

    def test_passes_multi_stage(self, parse_inline):
        df = parse_inline("""
            FROM golang:1.22 AS builder
            RUN go build -o /app .

            FROM gcr.io/distroless/static:nonroot
            COPY --from=builder /app /app
            CMD ["/app"]
        """)
        result = self.rule.check(df)
        assert result.passed

    def test_passes_no_build_tools(self, parse_inline):
        df = parse_inline("""
            FROM python:3.12-slim
            RUN pip install flask
            CMD ['python', 'app.py']
        """)
        result = self.rule.check(df)
        assert result.passed


# ============================================================================ DH005 NoHealthcheck


class TestNoHealthcheckRule:
    rule = NoHealthcheckRule()

    def test_flags_missing_healthcheck(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nCMD ['bash']")
        result = self.rule.check(df)
        assert not result.passed

    def test_passes_with_healthcheck(self, parse_inline):
        df = parse_inline("""
            FROM ubuntu:22.04
            HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1
            CMD ['bash']
        """)
        result = self.rule.check(df)
        assert result.passed

    def test_finding_is_fixable(self, parse_inline):
        df = parse_inline("FROM ubuntu:22.04\nCMD ['bash']")
        result = self.rule.check(df)
        assert any(f.fixable for f in result.findings)

    def test_severity_is_low(self):
        assert self.rule.SEVERITY == Severity.LOW


# ============================================================================ DH006 SecretsInEnv


class TestSecretsInEnvRule:
    rule = SecretsInEnvRule()

    def test_flags_hardcoded_password(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nENV DATABASE_PASSWORD=supersecret123\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert critical

    def test_flags_api_key(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nENV API_KEY=abc123xyz\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_flags_arg_with_default_secret(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nARG SECRET_TOKEN=my-secret\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_passes_empty_env_placeholder(self, parse_inline):
        # Empty placeholder or template — warn at MEDIUM, not CRITICAL.
        df = parse_inline("FROM alpine:3.19\nENV DATABASE_PASSWORD=\nCMD ['x']")
        result = self.rule.check(df)
        # Should be MEDIUM at most, not CRITICAL.
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert not critical

    def test_passes_non_secret_env(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nENV APP_PORT=8080\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed

    def test_severity_is_critical(self):
        assert self.rule.SEVERITY == Severity.CRITICAL


# ============================================================================ DH007 AddInstruction


class TestAddInstructionRule:
    rule = AddInstructionRule()

    def test_flags_local_file_add(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nADD app.py /app/app.py\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_flags_remote_url_add(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nADD https://example.com/setup.sh /tmp/\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed
        # Remote URL should be HIGH severity.
        high = [f for f in result.findings if f.severity == Severity.HIGH]
        assert high

    def test_info_for_tar_add(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nADD app.tar.gz /app/\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed
        info = [f for f in result.findings if f.severity == Severity.INFO]
        assert info

    def test_passes_copy(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nCOPY app.py /app/app.py\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed

    def test_local_file_add_is_fixable(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nADD app.py /app/app.py\nCMD ['x']")
        result = self.rule.check(df)
        fixable = [f for f in result.findings if f.fixable]
        assert fixable


# ============================================================================ DH008 AptHygiene


class TestAptHygieneRule:
    rule = AptHygieneRule()

    def test_flags_missing_cache_cleanup(self, parse_inline):
        df = parse_inline(
            "FROM ubuntu:22.04\nRUN apt-get install -y curl\nCMD ['x']"
        )
        result = self.rule.check(df)
        assert not result.passed
        assert any("cache" in f.message.lower() or "lists" in f.message.lower()
                   for f in result.findings)

    def test_flags_missing_no_install_recommends(self, parse_inline):
        df = parse_inline(
            "FROM ubuntu:22.04\n"
            "RUN apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
            "CMD ['x']"
        )
        result = self.rule.check(df)
        assert not result.passed
        assert any("recommends" in f.message.lower() for f in result.findings)

    def test_flags_update_without_install(self, parse_inline):
        df = parse_inline(
            "FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl\nCMD ['x']"
        )
        result = self.rule.check(df)
        assert not result.passed
        assert any("update" in f.message.lower() for f in result.findings)

    def test_passes_full_hygiene(self, parse_inline):
        df = parse_inline("""
            FROM ubuntu:22.04
            RUN apt-get update \\
                && apt-get install -y --no-install-recommends curl=7.88.1-10 \\
                && rm -rf /var/lib/apt/lists/*
            CMD ['x']
        """)
        result = self.rule.check(df)
        assert result.passed

    def test_flags_apk_without_no_cache(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nRUN apk add curl\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_passes_apk_with_no_cache(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nRUN apk add --no-cache curl\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed


# ============================================================================ DH009 PrivilegedPort


class TestPrivilegedPortRule:
    rule = PrivilegedPortRule()

    def test_flags_port_80(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nEXPOSE 80\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_flags_port_443(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nEXPOSE 443\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_flags_port_22(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nEXPOSE 22\nCMD ['x']")
        result = self.rule.check(df)
        assert not result.passed

    def test_passes_port_8080(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nEXPOSE 8080\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed

    def test_passes_port_1024(self, parse_inline):
        # 1024 is the boundary — should pass (not strictly < 1024).
        df = parse_inline("FROM alpine:3.19\nEXPOSE 1024\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed

    def test_flags_multiple_privileged_ports(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nEXPOSE 80 443\nCMD ['x']")
        result = self.rule.check(df)
        assert len(result.findings) == 2


# ============================================================================ DH010 FileOwnership


class TestFileOwnershipRule:
    rule = FileOwnershipRule()

    def test_flags_copy_without_chown(self, parse_inline):
        df = parse_inline("""
            FROM alpine:3.19
            RUN adduser -D appuser
            USER appuser
            COPY app.py /app/app.py
            CMD ['x']
        """)
        result = self.rule.check(df)
        assert not result.passed

    def test_passes_copy_with_chown(self, parse_inline):
        df = parse_inline("""
            FROM alpine:3.19
            RUN adduser -D appuser
            USER appuser
            COPY --chown=appuser:appuser app.py /app/app.py
            CMD ['x']
        """)
        result = self.rule.check(df)
        assert result.passed

    def test_does_not_flag_when_no_user_set(self, parse_inline):
        # No USER instruction — DH001 covers this, DH010 should not double-report.
        df = parse_inline("FROM alpine:3.19\nCOPY app.py /app/\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed

    def test_does_not_flag_when_user_is_root(self, parse_inline):
        df = parse_inline("FROM alpine:3.19\nUSER root\nCOPY app.py /app/\nCMD ['x']")
        result = self.rule.check(df)
        assert result.passed

    def test_finding_is_fixable(self, parse_inline):
        df = parse_inline("""
            FROM alpine:3.19
            RUN adduser -D appuser
            USER appuser
            COPY app.py /app/app.py
            CMD ['x']
        """)
        result = self.rule.check(df)
        assert any(f.fixable for f in result.findings)


# ============================================================================ integration: full fixture scans


class TestFixtureScan:
    def _run_all(self, parse_inline, content):
        from dockerfile_hardener.rules import ALL_RULES
        df = parse_inline(content)
        return [r.check(df) for r in ALL_RULES]

    def test_insecure_fixture_has_many_findings(self, fixture_path):
        from dockerfile_hardener.parser import parse_dockerfile
        from dockerfile_hardener.rules import ALL_RULES
        df = parse_dockerfile(fixture_path("Dockerfile.insecure"))
        results = [r.check(df) for r in ALL_RULES]
        all_findings = [f for r in results for f in r.findings]
        assert len(all_findings) >= 8, (
            f"Expected at least 8 findings from insecure fixture, got {len(all_findings)}"
        )

    def test_secure_fixture_is_clean(self, fixture_path):
        from dockerfile_hardener.parser import parse_dockerfile
        from dockerfile_hardener.rules import ALL_RULES
        df = parse_dockerfile(fixture_path("Dockerfile.secure"))
        results = [r.check(df) for r in ALL_RULES]
        all_findings = [f for r in results for f in r.findings]
        critical_high = [
            f for f in all_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        assert not critical_high, (
            "Secure fixture should have no CRITICAL/HIGH findings; got: "
            + ", ".join(f"{f.rule_id}: {f.message}" for f in critical_high)
        )
