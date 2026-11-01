
import hashlib
import json
import re
from collections import defaultdict
from typing import Any


# =========================================================
# 1. RISK CONFIGURATION
# =========================================================

SEVERITY_WEIGHT = {
    "INFO": 5,
    "LOW": 15,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 90,
    "UNKNOWN": 20,
}

CONFIDENCE_WEIGHT = {
    "LOW": 0.45,
    "MEDIUM": 0.70,
    "HIGH": 0.90,
    "UNKNOWN": 0.50,
}

RISK_LEVELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (35, "MEDIUM"),
    (15, "LOW"),
    (0, "INFO"),
]


# =========================================================
# 2. NORMALIZATION HELPERS
# =========================================================

def _text(value: Any) -> str:
    """Convert a value into safe text for analysis."""

    if value is None:
        return ""

    if isinstance(value, str):
        return value

    if isinstance(value, (dict, list, tuple, set)):
        try:
            return json.dumps(
                value,
                sort_keys=True,
                default=str,
            )
        except (TypeError, ValueError):
            return str(value)

    return str(value)


def _normalize_severity(value: Any) -> str:
    """Normalize severity into a supported category."""

    severity = _text(value).upper()

    return (
        severity
        if severity in SEVERITY_WEIGHT
        else "UNKNOWN"
    )


def _normalize_confidence(value: Any) -> str:
    """Normalize confidence into a supported category."""

    confidence = _text(value).upper()

    return (
        confidence
        if confidence in CONFIDENCE_WEIGHT
        else "UNKNOWN"
    )


# =========================================================
# 3. DUPLICATE DETECTION
# =========================================================

def _fingerprint(finding: dict) -> str:
    """
    Create a stable fingerprint for duplicate detection.

    Findings are considered duplicates when their rule,
    file, line and evidence match.
    """

    evidence_text = _text(
        finding.get("evidence")
    )

    identity = {
        "rule_id": _text(
            finding.get("rule_id")
        ).lower(),

        "file": _text(
            finding.get("file")
        ).replace("\\", "/").lower(),

        "line": finding.get("line"),

        "evidence": re.sub(
            r"\s+",
            " ",
            evidence_text,
        ).lower(),
    }

    encoded = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    return hashlib.sha256(encoded).hexdigest()


# =========================================================
# 4. FINDING NORMALIZATION
# =========================================================

def normalize_finding(finding: dict) -> dict:
    """
    Normalize a scanner finding without discarding
    original evidence or other finding information.
    """

    normalized = dict(finding)

    normalized["rule_id"] = (
        _text(finding.get("rule_id"))
        or "UNKNOWN-RULE"
    )

    normalized["severity"] = _normalize_severity(
        finding.get("severity")
    )

    normalized["confidence"] = _normalize_confidence(
        finding.get("confidence")
    )

    normalized["file"] = (
        _text(finding.get("file"))
        or None
    )

    # Preserve original evidence.
    normalized["evidence"] = finding.get(
        "evidence",
        [],
    )

    # Separate text representation for analysis.
    normalized["evidence_text"] = _text(
        finding.get("evidence")
    )

    normalized["fingerprint"] = _fingerprint(
        finding
    )

    normalized["original_severity"] = (
        normalized["severity"]
    )

    return normalized


# =========================================================
# 5. RISK LEVEL CALCULATION
# =========================================================

def _risk_level(score: int) -> str:
    """Convert numerical risk into a severity category."""

    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            return label

    return "INFO"


# =========================================================
# 6. CONTEXTUAL CLASSIFICATION
# =========================================================

def _classify_context(
    finding: dict,
) -> tuple[str, str, float]:
    """
    Conservatively classify a finding.

    SUSPICIOUS:
        Strong security indicators or a specific
        source-to-sink taint finding.

    INFORMATIONAL:
        Environment-variable access alone.

    NEEDS_REVIEW:
        Behaviour that may be legitimate or malicious.

    A NEEDS_REVIEW result is not a safe verdict.
    """

    rule = _text(
        finding.get("rule_id")
    ).lower()

    title = _text(
        finding.get("title")
    ).lower()

    description = _text(
        finding.get("description")
    ).lower()

    evidence = _text(
        finding.get("evidence_text")
    ).lower()

    combined = " ".join(
        (
            rule,
            title,
            description,
            evidence,
        )
    )

    # -----------------------------------------------------
    # PRIORITY 1: SOURCE-TO-SINK COMMAND INJECTION
    # -----------------------------------------------------

    if rule == "py-taint-cmd-001":
        return (
            "SUSPICIOUS",
            (
                "Untrusted input was statically traced to "
                "process execution. This is a strong "
                "command-injection indicator and requires "
                "investigation; exploitability is not confirmed."
            ),
            1.0,
        )

    # -----------------------------------------------------
    # PRIORITY 2: ENVIRONMENT VARIABLE ACCESS
    # -----------------------------------------------------

    if (
        rule == "py-secret-source-001"
        or "environment variable access" in title
        or "os.environ.get detected" in evidence
    ):
        return (
            "INFORMATIONAL",
            (
                "Environment variable access alone is not "
                "evidence of credential theft or exfiltration."
            ),
            0.0,
        )

    # -----------------------------------------------------
    # PRIORITY 3: STRONG SECURITY INDICATORS
    # -----------------------------------------------------

    high_risk_indicators = (
        "honeytoken",
        "credential theft",
        "exfiltration",
        "obfuscated download",
        "remote code execution",
    )

    if any(
        term in combined
        for term in high_risk_indicators
    ):
        return (
            "SUSPICIOUS",
            (
                "Strong security indicator detected; "
                "retain the finding for investigation."
            ),
            1.0,
        )

    # -----------------------------------------------------
    # PRIORITY 4: PROCESS EXECUTION
    # -----------------------------------------------------

    if (
        "subprocess" in combined
        or "process_execution" in combined
        or "process execution" in combined
    ):

        if re.search(
            r"\bshell\s*=\s*true\b(?!\s*:\s*false)",
            combined,
        ):
            return (
                "NEEDS_REVIEW",
                (
                    "Shell-based process execution can be "
                    "legitimate or malicious. Review the "
                    "command source and its validation."
                ),
                0.35,
            )

        return (
            "NEEDS_REVIEW",
            (
                "Process execution can be legitimate or "
                "malicious; additional context is required."
            ),
            0.20,
        )

    # -----------------------------------------------------
    # PRIORITY 5: NETWORK ACTIVITY
    # -----------------------------------------------------

    network_indicators = (
        "network",
        "socket",
        "http",
        "urlopen",
    )

    if any(
        term in combined
        for term in network_indicators
    ):
        return (
            "NEEDS_REVIEW",
            (
                "Network activity requires additional "
                "context to determine its security significance."
            ),
            0.30,
        )

    # -----------------------------------------------------
    # DEFAULT CLASSIFICATION
    # -----------------------------------------------------

    return (
        "NEEDS_REVIEW",
        (
            "No sufficiently strong benign explanation "
            "is available."
        ),
        0.50,
    )


# =========================================================
# 7. MAIN STAGE 5 ENGINE
# =========================================================

def assess_findings(findings: list[dict]) -> dict:
    """
    Run the SCG Smart False-Alarm Filter.

    Processing:
        1. Normalize findings.
        2. Detect exact duplicates.
        3. Classify contextual behaviour.
        4. Determine risk eligibility.
        5. Correlate findings by file.
        6. Calculate contextual risk.
        7. Generate explanations and statistics.
    """

    if not isinstance(findings, list):
        raise TypeError(
            "findings must be a list"
        )

    normalized = []

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        item = normalize_finding(finding)

        normalized.append(item)

    # -----------------------------------------------------
    # STEP 1: DEDUPLICATION
    # -----------------------------------------------------

    unique = {}

    duplicate_groups = defaultdict(list)

    for finding in normalized:

        fingerprint = finding["fingerprint"]

        if fingerprint not in unique:

            unique[fingerprint] = finding

        else:

            duplicate_groups[fingerprint].append(
                finding.get("finding_id")
            )

    deduplicated = list(
        unique.values()
    )

    # -----------------------------------------------------
    # STEP 2: CONTEXTUAL CLASSIFICATION
    # -----------------------------------------------------

    assessed = []

    for finding in deduplicated:

        (
            classification,
            explanation,
            multiplier,
        ) = _classify_context(finding)

        severity = finding["original_severity"]

        base_score = SEVERITY_WEIGHT[
            severity
        ]

        confidence = CONFIDENCE_WEIGHT[
            finding["confidence"]
        ]

        # Evidence-only findings must not independently
        # increase the contextual risk score.

        score_contribution = finding.get(
            "score_contribution",
            0,
        )

        try:
            risk_eligible = (
                float(score_contribution) > 0
                and classification != "INFORMATIONAL"
                and multiplier > 0
            )
        except (TypeError, ValueError):
            risk_eligible = False

        adjusted_score = (
            round(
                base_score
                * confidence
                * multiplier
            )
            if risk_eligible
            else 0
        )

        item = dict(finding)

        item.update({
            "classification": classification,
            "explanation": explanation,
            "context_multiplier": multiplier,
            "adjusted_score": adjusted_score,
            "risk_eligible": risk_eligible,
        })

        assessed.append(item)

    # -----------------------------------------------------
    # STEP 3: CORRELATION BY FILE
    # -----------------------------------------------------

    correlation_groups = defaultdict(list)

    for finding in assessed:

        file_name = finding.get("file")

        if file_name:

            correlation_groups[file_name].append(
                finding.get("finding_id")
            )

    correlated = []

    for file_name, finding_ids in correlation_groups.items():

        group_id = hashlib.sha256(
            file_name.encode("utf-8")
        ).hexdigest()[:12]

        correlated.append({
            "group_id": group_id,
            "file": file_name,
            "finding_ids": finding_ids,
            "finding_count": len(finding_ids),
        })

    # -----------------------------------------------------
    # STEP 4: CONTEXTUAL RISK CALCULATION
    # -----------------------------------------------------

    # Use the highest eligible adjusted finding score.
    # Do not sum duplicate or correlated observations.

    risk_score = min(
        100,
        max(
            (
                item["adjusted_score"]
                for item in assessed
                if item["risk_eligible"]
            ),
            default=0,
        ),
    )

    risk_level = _risk_level(
        risk_score
    )

    # -----------------------------------------------------
    # STEP 5: SUMMARY STATISTICS
    # -----------------------------------------------------

    suspicious_count = sum(
        item["classification"] == "SUSPICIOUS"
        for item in assessed
    )

    review_count = sum(
        item["classification"] == "NEEDS_REVIEW"
        for item in assessed
    )

    informational_count = sum(
        item["classification"] == "INFORMATIONAL"
        for item in assessed
    )

    risk_eligible_count = sum(
        item["risk_eligible"]
        for item in assessed
    )

    evidence_only_count = sum(
        not item["risk_eligible"]
        for item in assessed
    )

    # -----------------------------------------------------
    # STEP 6: FINAL REPORT
    # -----------------------------------------------------

    return {
        "engine": "SCG Smart False-Alarm Filter",
        "status": "completed",

        "summary": {
            "original_findings": len(findings),
            "normalized_findings": len(normalized),
            "unique_findings": len(deduplicated),
            "duplicates_removed": (
                len(normalized) - len(deduplicated)
            ),
            "suspicious_findings": suspicious_count,
            "needs_review": review_count,
            "informational_findings": informational_count,
            "risk_eligible_findings": risk_eligible_count,
            "evidence_only_findings": evidence_only_count,
        },

        "risk": {
            "score": risk_score,
            "severity": risk_level,
            "method": (
                "maximum_context_adjusted_finding_score"
            ),
        },

        "findings": assessed,

        "duplicate_groups": [
            {
                "fingerprint": fingerprint,
                "duplicate_finding_ids": ids,
            }
            for fingerprint, ids in duplicate_groups.items()
        ],

        "correlation_groups": correlated,

        "limitations": [
            "Context classification uses conservative static rules.",
            "A needs-review classification is not a benign verdict.",
            "Cross-file behavioural correlation is not implemented.",
            "Runtime events must be supplied separately for multimodal correlation.",
            "Risk score is an experimental heuristic, not a calibrated probability.",
            "Only findings with positive score contributions affect contextual risk.",
            "Static taint analysis does not confirm exploitability.",
        ],
    }
