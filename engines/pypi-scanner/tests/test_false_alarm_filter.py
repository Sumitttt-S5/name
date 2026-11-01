
import sys
from pathlib import Path

# Make the scanner package importable when tests run from project root.
SCANNER_ROOT = Path(__file__).resolve().parents[1]
if str(SCANNER_ROOT) not in sys.path:
    sys.path.insert(0, str(SCANNER_ROOT))

from scanner.false_alarm_filter import (
    assess_findings,
    normalize_finding,
)


def sample_finding(**overrides):
    finding = {
        "finding_id": "F-001",
        "stage": 2,
        "rule_id": "SCG-TEST-001",
        "title": "Test security finding",
        "description": "A test finding for Stage 5.",
        "severity": "HIGH",
        "confidence": "HIGH",
        "file": "src/example.py",
        "line": 10,
        "evidence": ["suspicious_function()", "test evidence"],
        "mitre_techniques": [],
        "score_contribution": 20,
    }

    finding.update(overrides)
    return finding


def test_empty_findings():
    report = assess_findings([])

    assert report["status"] == "completed"
    assert report["summary"]["original_findings"] == 0
    assert report["summary"]["unique_findings"] == 0
    assert report["risk"]["score"] == 0
    assert report["findings"] == []


def test_normalization_preserves_original_evidence_list():
    original_evidence = [
        "subprocess.Popen(command)",
        "Execution evidence",
    ]

    finding = sample_finding(evidence=original_evidence)

    normalized = normalize_finding(finding)

    assert normalized["evidence"] == original_evidence
    assert isinstance(normalized["evidence"], list)

    assert isinstance(normalized["evidence_text"], str)
    assert "subprocess.Popen(command)" in normalized["evidence_text"]


def test_exact_duplicate_findings_are_removed():
    first = sample_finding(finding_id="F-001")
    second = sample_finding(finding_id="F-002")

    report = assess_findings([first, second])

    assert report["summary"]["original_findings"] == 2
    assert report["summary"]["unique_findings"] == 1
    assert report["summary"]["duplicates_removed"] == 1
    assert len(report["findings"]) == 1
    assert len(report["duplicate_groups"]) == 1


def test_findings_on_different_lines_are_not_duplicates():
    first = sample_finding(
        finding_id="F-001",
        line=10,
    )

    second = sample_finding(
        finding_id="F-002",
        line=20,
    )

    report = assess_findings([first, second])

    assert report["summary"]["unique_findings"] == 2
    assert report["summary"]["duplicates_removed"] == 0


def test_honeytoken_finding_remains_suspicious():
    finding = sample_finding(
        rule_id="SCG-HONEYTOKEN-001",
        title="Honeytoken access detected",
        description="A package accessed a fake credential file.",
        evidence=["Accessed /decoys/.env.fake"],
    )

    report = assess_findings([finding])

    result = report["findings"][0]

    assert result["classification"] == "SUSPICIOUS"
    assert result["context_multiplier"] == 1.0
    assert result["severity"] == "HIGH"
    assert result["original_severity"] == "HIGH"


def test_process_execution_requires_review():
    finding = sample_finding(
        rule_id="SCG-PROCESS-001",
        title="Process execution detected",
        description="Package executed a subprocess.",
        evidence=["subprocess.Popen('/bin/echo')"],
    )

    report = assess_findings([finding])

    result = report["findings"][0]

    assert result["classification"] == "NEEDS_REVIEW"
    assert "additional context" in result["explanation"]


def test_network_activity_requires_review():
    finding = sample_finding(
        rule_id="SCG-NETWORK-001",
        title="Network connection detected",
        evidence=["socket.connect(destination)"],
    )

    report = assess_findings([finding])

    assert report["findings"][0]["classification"] == "NEEDS_REVIEW"


def test_findings_are_correlated_by_file():
    first = sample_finding(
        finding_id="F-001",
        line=10,
    )

    second = sample_finding(
        finding_id="F-002",
        line=20,
        rule_id="SCG-TEST-002",
    )

    report = assess_findings([first, second])

    assert len(report["correlation_groups"]) == 1

    group = report["correlation_groups"][0]

    assert group["file"] == "src/example.py"
    assert group["finding_count"] == 2
    assert set(group["finding_ids"]) == {"F-001", "F-002"}


def test_risk_score_is_bounded():
    finding = sample_finding(
        severity="CRITICAL",
        confidence="HIGH",
        title="Remote code execution detected",
        evidence=["remote code execution"],
    )

    report = assess_findings([finding])

    assert 0 <= report["risk"]["score"] <= 100


def test_invalid_entries_are_ignored():
    findings = [
        sample_finding(),
        "invalid finding",
        None,
        123,
    ]

    report = assess_findings(findings)

    assert report["summary"]["original_findings"] == 4
    assert report["summary"]["normalized_findings"] == 1
    assert report["summary"]["unique_findings"] == 1

def test_evidence_only_finding_does_not_increase_risk():
    finding = sample_finding(
        severity="CRITICAL",
        confidence="HIGH",
        score_contribution=0,
        title="Honeytoken access detected",
        evidence=["honeytoken accessed"],
    )

    report = assess_findings([finding])

    result = report["findings"][0]

    # It must remain suspicious.
    assert result["classification"] == "SUSPICIOUS"

    # But it must not increase the risk score.
    assert result["risk_eligible"] is False
    assert result["adjusted_score"] == 0
    assert report["risk"]["score"] == 0

    # It must be counted as evidence-only.
    assert report["summary"]["evidence_only_findings"] == 1

def test_environment_variable_access_is_informational():
    finding = sample_finding(
        rule_id="PY-SECRET-SOURCE-001",
        title="Environment variable access",
        severity="LOW",
        confidence="LOW",
        score_contribution=1,
        evidence=["os.environ.get detected"],
    )

    report = assess_findings([finding])
    result = report["findings"][0]

    assert result["classification"] == "INFORMATIONAL"
    assert result["risk_eligible"] is False
    assert result["adjusted_score"] == 0
    assert report["risk"]["score"] == 0
    assert report["summary"]["informational_findings"] == 1


def test_shell_execution_has_reduced_contextual_score():
    finding = sample_finding(
        rule_id="PY-PROCESS-002",
        title="Subprocess execution",
        severity="HIGH",
        confidence="MEDIUM",
        score_contribution=5,
        evidence=["subprocess.run detected; shell=True: True"],
    )

    report = assess_findings([finding])
    result = report["findings"][0]

    assert result["classification"] == "NEEDS_REVIEW"
    assert result["risk_eligible"] is True
    assert result["adjusted_score"] == 17
    assert report["risk"]["score"] == 17

def test_shell_false_does_not_use_shell_true_multiplier():
    finding = sample_finding(
        rule_id="PY-PROCESS-002",
        title="Subprocess execution",
        severity="MEDIUM",
        confidence="MEDIUM",
        score_contribution=2,
        evidence=["subprocess.run detected; shell=True: False"],
    )

    report = assess_findings([finding])
    result = report["findings"][0]

    assert result["context_multiplier"] == 0.20
    assert result["classification"] == "NEEDS_REVIEW"
