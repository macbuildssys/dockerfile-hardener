"""
Tests for dockerfile_hardener.reporter
"""

from __future__ import annotations

import io
import json

from dockerfile_hardener.reporter import (
    compute_score,
    report_html,
    report_json,
    report_sarif,
    report_table,
    score_grade,
)
from dockerfile_hardener.rules import ALL_RULES
from dockerfile_hardener.rules.base import Finding, RuleResult, Severity


def _results_from_fixture(fixture_path, name):
    from dockerfile_hardener.parser import parse_dockerfile

    df = parse_dockerfile(fixture_path(name))
    return [r.check(df) for r in ALL_RULES]

# scoring

def test_compute_score_perfect():
    assert compute_score([]) == 100


def test_compute_score_deducts_critical():
    finding = Finding(
        rule_id="DH001", rule_name="R", severity=Severity.CRITICAL,
        message="m", line_number=1, fix_description=None,
    )
    score = compute_score([finding])
    assert score == 100 - Severity.CRITICAL.score_deduction


def test_compute_score_floors_at_zero():
    findings = [
        Finding(
            rule_id="X", rule_name="R", severity=Severity.CRITICAL,
            message="m", line_number=i, fix_description=None,
        )
        for i in range(20)
    ]
    assert compute_score(findings) == 0

def test_score_grade_bands():
    assert score_grade(100) == "A"
    assert score_grade(90) == "A"
    assert score_grade(89) == "B"
    assert score_grade(75) == "B"
    assert score_grade(74) == "C"
    assert score_grade(60) == "C"
    assert score_grade(59) == "D"
    assert score_grade(40) == "D"
    assert score_grade(39) == "F"
    assert score_grade(0) == "F"

# JSON reporter

class TestJsonReporter:
    def test_valid_json_structure(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        report_json(results, "Dockerfile.insecure", out=buf)
        data = json.loads(buf.getvalue())
        assert "findings" in data
        assert "score" in data
        assert "grade" in data
        assert "summary" in data
        assert "tool" in data
        assert data["tool"] == "dockerfile-hardener"

    def test_findings_have_required_fields(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        report_json(results, "Dockerfile.insecure", out=buf)
        data = json.loads(buf.getvalue())
        for f in data["findings"]:
            assert "rule_id" in f
            assert "severity" in f
            assert "message" in f

    def test_empty_findings_score_100(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.secure")
        buf = io.StringIO()
        report_json(results, "Dockerfile.secure", out=buf)
        data = json.loads(buf.getvalue())
        assert data["score"] >= 60

    def test_returns_exit_code_1_when_findings(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        code = report_json(results, "Dockerfile.insecure", out=buf)
        assert code == 1

    def test_returns_exit_code_0_when_clean(self):
        results = [RuleResult(rule_id="DH001", rule_name="RootUser")]
        buf = io.StringIO()
        code = report_json(results, "Dockerfile", out=buf)
        assert code == 0

# SARIF reporter

class TestSarifReporter:
    def test_valid_sarif_schema(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        report_sarif(results, "Dockerfile.insecure", out=buf)
        data = json.loads(buf.getvalue())
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_sarif_results_have_locations(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        report_sarif(results, "Dockerfile.insecure", out=buf)
        data = json.loads(buf.getvalue())
        for result in data["runs"][0]["results"]:
            assert "locations" in result
            assert result["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uri"]

    def test_sarif_levels_map_correctly(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        report_sarif(results, "Dockerfile.insecure", out=buf)
        data = json.loads(buf.getvalue())
        levels = {r["level"] for r in data["runs"][0]["results"]}
        assert levels.issubset({"error", "warning", "note", "none"})

# HTML reporter

class TestHtmlReporter:
    def test_produces_html_output(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        report_html(results, "Dockerfile.insecure", out=buf)
        html = buf.getvalue()
        assert "<!DOCTYPE html>" in html
        assert "dockerfile-hardener" in html

    def test_html_contains_score(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        report_html(results, "Dockerfile.insecure", out=buf)
        html = buf.getvalue()
        assert "/100" in html

    def test_html_contains_severity_badges(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        report_html(results, "Dockerfile.insecure", out=buf)
        html = buf.getvalue()
        assert "CRITICAL" in html or "HIGH" in html

    def test_html_pass_banner_when_no_findings(self):
        results = [RuleResult(rule_id="DH001", rule_name="RootUser")]
        buf = io.StringIO()
        report_html(results, "Dockerfile", out=buf)
        html = buf.getvalue()
        assert "No issues found" in html

    def test_html_written_to_file(self, tmp_path, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        out_file = str(tmp_path / "report.html")
        report_html(results, "Dockerfile.insecure", output_path=out_file)
        content = (tmp_path / "report.html").read_text()
        assert "<!DOCTYPE html>" in content

# Table reporter

class TestTableReporter:
    def test_table_returns_exit_1_on_findings(self, fixture_path):
        results = _results_from_fixture(fixture_path, "Dockerfile.insecure")
        buf = io.StringIO()
        code = report_table(results, "Dockerfile.insecure", out=buf)
        assert code == 1

    def test_table_returns_exit_0_on_no_findings(self):
        results = [RuleResult(rule_id="DH001", rule_name="RootUser")]
        buf = io.StringIO()
        code = report_table(results, "Dockerfile", out=buf)
        assert code == 0
