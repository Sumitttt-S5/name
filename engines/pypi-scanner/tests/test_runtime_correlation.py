
import sys
from pathlib import Path

# Make backend importable when tests run from project root.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = PROJECT_ROOT / "backend"

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.services.runtime_correlation import (
    normalize_runtime_events,
    correlate_behaviours,
    prepare_unified_findings,
)


def test_honeytoken_runtime_event_is_normalized():
    report = {
        "report_id": "TEST-001",
        "events": [
            {
                "event_id": "E-1",
                "event_type": "HONEYTOKEN_ACCESS",
                "severity": "HIGH",
                "source": "audit_hook",
                "details": {"path": "/decoys/.env.fake"},
            }
        ],
    }

    findings = normalize_runtime_events(report)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SCG-RUNTIME-HONEYTOKEN-001"
    assert findings[0]["runtime_category"] == "honeytoken_access"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["confidence"] == "HIGH"
    assert "/decoys/.env.fake" in str(findings[0]["evidence"])


def test_process_runtime_event_is_normalized():
    report = {
        "events": [
            {
                "event_type": "PROCESS_EXECUTION",
                "severity": "MEDIUM",
                "details": {"command": "/bin/echo"},
            }
        ]
    }

    findings = normalize_runtime_events(report)

    assert len(findings) == 1
    assert findings[0]["runtime_category"] == "process_execution"
    assert findings[0]["rule_id"] == "SCG-RUNTIME-PROCESS-001"


def test_network_runtime_event_is_normalized():
    report = {
        "events": [
            {
                "event_type": "NETWORK_ATTEMPT",
                "severity": "HIGH",
                "details": {"destination": "192.0.2.1"},
            }
        ]
    }

    findings = normalize_runtime_events(report)

    assert len(findings) == 1
    assert findings[0]["runtime_category"] == "network_activity"
    assert findings[0]["rule_id"] == "SCG-RUNTIME-NETWORK-001"


def test_unknown_runtime_event_is_preserved_as_observation():
    report = {
        "events": [
            {
                "event_type": "UNKNOWN_EVENT",
                "severity": "LOW",
                "details": {"message": "test"},
            }
        ]
    }

    findings = normalize_runtime_events(report)

    assert len(findings) == 1
    assert findings[0]["runtime_category"] == "other_runtime_activity"
    assert findings[0]["rule_id"] == "SCG-RUNTIME-OBSERVATION-001"


def test_invalid_runtime_events_are_skipped():
    report = {
        "events": [
            None,
            "invalid event",
            {},
            {
                "event_type": "PROCESS_EXECUTION",
                "severity": "MEDIUM",
                "details": {},
            },
        ]
    }

    findings = normalize_runtime_events(report)

    assert len(findings) == 1
    assert findings[0]["runtime_category"] == "process_execution"


def test_invalid_runtime_severity_defaults_to_medium():
    report = {
        "events": [
            {
                "event_type": "PROCESS_EXECUTION",
                "severity": "UNKNOWN",
                "details": {},
            }
        ]
    }

    findings = normalize_runtime_events(report)

    assert findings[0]["severity"] == "MEDIUM"


def test_static_and_runtime_process_findings_are_correlated():
    static_findings = [
        {
            "finding_id": "STATIC-001",
            "rule_id": "PY-PROCESS-002",
            "title": "Subprocess execution",
            "evidence": ["subprocess.run detected"],
        }
    ]

    runtime_findings = [
        {
            "finding_id": "RUNTIME-001",
            "runtime_category": "process_execution",
        }
    ]

    correlations = correlate_behaviours(
        static_findings,
        runtime_findings,
    )

    assert len(correlations) == 1
    assert correlations[0]["category"] == "process_execution"
    assert correlations[0]["static_count"] == 1
    assert correlations[0]["runtime_count"] == 1
    assert correlations[0]["confidence"] == "LOW"


def test_unrelated_categories_are_not_correlated():
    static_findings = [
        {
            "finding_id": "STATIC-001",
            "title": "Subprocess execution",
            "evidence": ["subprocess.run"],
        }
    ]

    runtime_findings = [
        {
            "finding_id": "RUNTIME-001",
            "runtime_category": "network_activity",
        }
    ]

    correlations = correlate_behaviours(
        static_findings,
        runtime_findings,
    )

    assert correlations == []


def test_prepare_unified_findings_combines_both_sources():
    static_findings = [
        {
            "finding_id": "STATIC-001",
            "rule_id": "PY-PROCESS-002",
            "title": "Subprocess execution",
            "evidence": ["subprocess.run detected"],
        }
    ]

    runtime_report = {
        "report_id": "TEST-002",
        "events": [
            {
                "event_id": "E-1",
                "event_type": "PROCESS_EXECUTION",
                "severity": "MEDIUM",
                "details": {"command": "/bin/echo"},
            }
        ],
    }

    result = prepare_unified_findings(
        static_findings,
        runtime_report,
    )

    assert len(result["static_findings"]) == 1
    assert len(result["runtime_findings"]) == 1
    assert len(result["combined_findings"]) == 2
    assert len(result["correlations"]) == 1
    assert result["summary"]["combined_findings"] == 2
    assert result["summary"]["correlated_behaviours"] == 1


def test_empty_reports_produce_empty_unified_findings():
    result = prepare_unified_findings([], {"events": []})

    assert result["static_findings"] == []
    assert result["runtime_findings"] == []
    assert result["combined_findings"] == []
    assert result["correlations"] == []
    assert result["summary"]["combined_findings"] == 0


def test_invalid_runtime_report_raises_type_error():
    try:
        normalize_runtime_events(None)
        assert False, "Expected TypeError"
    except TypeError:
        pass
