
import json
import re
from collections import defaultdict
from typing import Any


# =========================================================
# 1. HELPERS
# =========================================================

def _text(value: Any) -> str:
    """Convert event data into readable, safe text."""

    if value is None:
        return ""

    if isinstance(value, str):
        return value

    try:
        return json.dumps(
            value,
            sort_keys=True,
            default=str,
        )
    except (TypeError, ValueError):
        return str(value)


def _normalize_event_type(value: Any) -> str:
    """Normalize runtime event names."""

    return re.sub(
        r"[^A-Z0-9]+",
        "_",
        _text(value).upper(),
    ).strip("_")


def _event_category(event_type: str) -> str:
    """Map runtime event types to behaviour categories."""

    if "HONEYTOKEN" in event_type:
        return "honeytoken_access"

    if (
        "PROCESS" in event_type
        or "SUBPROCESS" in event_type
    ):
        return "process_execution"

    if (
        "NETWORK" in event_type
        or "SOCKET" in event_type
        or "CONNECTION" in event_type
    ):
        return "network_activity"

    return "other_runtime_activity"


# =========================================================
# 2. RUNTIME EVENT NORMALIZATION
# =========================================================

def normalize_runtime_events(
    runtime_report: dict,
) -> list[dict]:
    """
    Convert Docker runtime events into Stage 5-compatible
    security findings.

    Original event details are preserved as evidence.
    """

    if not isinstance(runtime_report, dict):
        raise TypeError(
            "runtime_report must be a dictionary."
        )

    events = runtime_report.get("events", [])

    if not isinstance(events, list):
        raise ValueError(
            "Runtime report events must be a list."
        )

    report_id = _text(
        runtime_report.get("report_id")
    ) or "unknown"

    findings = []

    for index, event in enumerate(events, start=1):

        if not isinstance(event, dict):
            continue

        event_type = _normalize_event_type(
            event.get("event_type")
        )

        if not event_type:
            continue

        category = _event_category(event_type)

        details = event.get("details", {})

        if not isinstance(details, dict):
            details = {
                "raw_details": _text(details)
            }

        severity = _text(
            event.get("severity")
        ).upper()

        if severity not in {
            "INFO",
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }:
            severity = "MEDIUM"

        event_id = event.get(
            "event_id",
            index,
        )

        evidence = [
            f"Runtime event: {event_type}",
            f"Event source: {_text(event.get('source'))}",
            f"Event timestamp: {_text(event.get('timestamp'))}",
            f"Runtime details: {_text(details)}",
        ]

        # -------------------------------------------------
        # HONEYTOKEN ACCESS
        # -------------------------------------------------

        if category == "honeytoken_access":

            rule_id = "SCG-RUNTIME-HONEYTOKEN-001"

            title = "Runtime honeytoken access"

            description = (
                "The package accessed a monitored decoy "
                "resource during sandbox execution. This is "
                "a strong indicator requiring investigation."
            )

            confidence = "HIGH"

        # -------------------------------------------------
        # PROCESS EXECUTION
        # -------------------------------------------------

        elif category == "process_execution":

            rule_id = "SCG-RUNTIME-PROCESS-001"

            title = "Runtime process execution"

            description = (
                "The sandbox observed the package initiating "
                "a process. Process execution can be legitimate "
                "or malicious and requires contextual review."
            )

            confidence = "HIGH"

        # -------------------------------------------------
        # NETWORK ACTIVITY
        # -------------------------------------------------

        elif category == "network_activity":

            rule_id = "SCG-RUNTIME-NETWORK-001"

            title = "Runtime network attempt"

            description = (
                "The sandbox observed an attempted network "
                "operation. This event does not establish that "
                "a connection was successfully completed."
            )

            confidence = "HIGH"

        # -------------------------------------------------
        # OTHER RUNTIME EVENTS
        # -------------------------------------------------

        else:

            rule_id = "SCG-RUNTIME-OBSERVATION-001"

            title = "Other runtime activity"

            description = (
                "The sandbox recorded a runtime event that "
                "requires additional contextual analysis."
            )

            confidence = "MEDIUM"

        findings.append({
            "finding_id": (
                f"SCG-RUNTIME-{report_id}-{event_id}"
            ),

            "stage": 4,

            "rule_id": rule_id,

            "title": title,

            "description": description,

            "severity": severity,

            "confidence": confidence,

            "file": None,

            "line": None,

            "evidence": evidence,

            "runtime_event_type": event_type,

            "runtime_event_id": event_id,

            "runtime_category": category,

            "runtime_timestamp": event.get("timestamp"),

            "runtime_details": details,

            "mitre_techniques": [],

            # Runtime observations contribute to Stage 5
            # contextual scoring.
            "score_contribution": 1,
        })

    return findings


# =========================================================
# 3. STATIC FINDING CATEGORY DETECTION
# =========================================================

def _static_category(finding: dict) -> str | None:
    """Identify the behaviour category of a static finding."""

    searchable = " ".join([
        _text(finding.get("rule_id")),
        _text(finding.get("title")),
        _text(finding.get("description")),
        _text(finding.get("evidence")),
    ]).lower()

    if (
        "honeytoken" in searchable
        or "decoy" in searchable
    ):
        return "honeytoken_access"

    if any(
        term in searchable
        for term in (
            "subprocess",
            "process_execution",
            "process execution",
            "os.system",
        )
    ):
        return "process_execution"

    if any(
        term in searchable
        for term in (
            "network",
            "socket",
            "urlopen",
            "requests.",
            "httpx.",
        )
    ):
        return "network_activity"

    return None


# =========================================================
# 4. STATIC + RUNTIME BEHAVIOUR CORRELATION
# =========================================================

def correlate_behaviours(
    static_findings: list[dict],
    runtime_findings: list[dict],
) -> list[dict]:
    """
    Identify behaviour categories observed by both
    static analysis and runtime analysis.

    This is category-level co-occurrence, not proof that
    both findings refer to the exact same source line.
    """

    if not isinstance(static_findings, list):
        raise TypeError(
            "static_findings must be a list."
        )

    if not isinstance(runtime_findings, list):
        raise TypeError(
            "runtime_findings must be a list."
        )

    static_groups = defaultdict(list)
    runtime_groups = defaultdict(list)

    # Group static findings.
    for index, finding in enumerate(static_findings):

        if not isinstance(finding, dict):
            continue

        category = _static_category(finding)

        if category:

            finding_id = finding.get(
                "finding_id",
                f"STATIC-{index + 1}",
            )

            static_groups[category].append(
                finding_id
            )

    # Group runtime findings.
    for index, finding in enumerate(runtime_findings):

        if not isinstance(finding, dict):
            continue

        category = finding.get(
            "runtime_category"
        )

        if category:

            finding_id = finding.get(
                "finding_id",
                f"RUNTIME-{index + 1}",
            )

            runtime_groups[category].append(
                finding_id
            )

    # Report only categories observed in both sources.
    correlations = []

    for category in sorted(
        set(static_groups) & set(runtime_groups)
    ):

        correlations.append({
            "category": category,

            "static_finding_ids": (
                static_groups[category]
            ),

            "runtime_finding_ids": (
                runtime_groups[category]
            ),

            "static_count": len(
                static_groups[category]
            ),

            "runtime_count": len(
                runtime_groups[category]
            ),

            "correlation_type": (
                "behavioural_category_co_occurrence"
            ),

            "confidence": "LOW",

            "explanation": (
                "Static and runtime analysis independently "
                "observed the same behaviour category. "
                "Exact source-level causation has not been "
                "established."
            ),
        })

    return correlations


# =========================================================
# 5. UNIFIED FINDING COLLECTION
# =========================================================

def prepare_unified_findings(
    static_findings: list[dict],
    runtime_report: dict,
) -> dict:
    """
    Prepare static and runtime findings for Stage 5.

    Returns normalized runtime findings, combined findings,
    and behavioural correlation results.
    """

    if not isinstance(static_findings, list):
        raise TypeError(
            "static_findings must be a list."
        )

    runtime_findings = normalize_runtime_events(
        runtime_report
    )

    correlations = correlate_behaviours(
        static_findings,
        runtime_findings,
    )

    combined_findings = (
        list(static_findings)
        + runtime_findings
    )

    return {
        "static_findings": list(static_findings),

        "runtime_findings": runtime_findings,

        "combined_findings": combined_findings,

        "correlations": correlations,

        "summary": {
            "static_findings": len(static_findings),

            "runtime_events": len(
                runtime_report.get("events", [])
            ),

            "runtime_findings": len(runtime_findings),

            "combined_findings": len(
                combined_findings
            ),

            "correlated_behaviours": len(
                correlations
            ),
        },
    }
