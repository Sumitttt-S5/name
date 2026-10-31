
import argparse
import json
import sys
import uuid
from pathlib import Path

# Locate the scanner directory and make its modules importable.
SCANNER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCANNER_DIR))

# Import scanner modules.
from scanner.file_discovery import discover_python_files
from scanner.parser import parse_python_file
from scanner.ast_analyzer import analyze_python_file
from scanner.taint_engine import analyze_taint


def get_severity(score: int) -> str:
    """Apply provisional risk bands."""
    if score >= 65:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def scan_directory(package_path: str) -> dict:
    root = Path(package_path).resolve()

    files = discover_python_files(root)
    findings = []
    issues = []
    analyzed = 0

    for file_path in files:
        parsed, issue = parse_python_file(file_path, root)

        if issue:
            issues.append({
                "file": str(file_path),
                "error": issue.error,
                "line": issue.line
            })
            continue

        analyzed += 1

        # Stage 2A: Detect suspicious AST behaviour.
        findings.extend(analyze_python_file(parsed))

        # Stage 2B: Track sensitive data from sources to sinks.
        findings.extend(
            analyze_taint(parsed.tree, parsed.path)
        )

    # Preliminary indicator score, not a malware probability.
    score = min(
        100,
        sum(f.score_contribution for f in findings)
    )

    return {
        "schema_version": "1.0.0",
        "scan_id": str(uuid.uuid4()),

        "package": {
            "name": root.name,
            "version": None,
            "ecosystem": "pypi",
            "artifact_hash": None,
            "artifact_filename": None
        },

        "scan_status": "PARTIAL" if issues else "COMPLETED",

        "risk": {
            "score": score,
            "severity": get_severity(score),
            "confidence": "LOW" if findings else "UNKNOWN",
            "explanation": (
                "Preliminary static-analysis indicator score. "
                "It is not a calibrated malware probability. "
                "A low score does not establish that a package is safe."
            )
        },

        "coverage": {
            "files_discovered": len(files),
            "files_analyzed": analyzed,
            "files_skipped": len(issues),
            "limitations": [
                "Only Python source files are analyzed.",
                "Taint analysis is sequential and intraprocedural.",
                "Complex control-flow propagation is not implemented.",
                "Cross-function taint propagation is not implemented.",
                "Package metadata and README claims are not analyzed yet.",
                "Previous-version comparison is not implemented yet.",
                "No dynamic sandbox execution has been performed."
            ]
        },

        "stages": {
            "stage_1_name_and_lie_detector": {
                "status": "NOT_AVAILABLE",
                "score": None,
                "summary": "Package identity and README comparison are pending."
            },

            "stage_2_password_and_gibberish_tracker": {
                "status": "PARTIAL",
                "score": score,
                "summary": (
                    "AST behaviour indicators and basic "
                    "source-to-sink taint analysis performed."
                )
            },

            "stage_3_update_hijack_detector": {
                "status": "NOT_AVAILABLE",
                "score": None,
                "summary": "Previous package version was not supplied."
            },

            "stage_4_fake_bait_sandbox": {
                "status": "NOT_AVAILABLE",
                "score": None,
                "summary": "Isolated sandbox is not implemented yet."
            },

            "stage_5_false_alarm_filter": {
                "status": "NOT_AVAILABLE",
                "score": None,
                "summary": "Evidence correlation is not implemented yet."
            },

            "stage_6_ai_reporter": {
                "status": "NOT_AVAILABLE",
                "score": None,
                "summary": "AI-assisted reporting is not implemented yet."
            }
        },

        "findings": [
            finding.to_dict() for finding in findings
        ],

        "parse_issues": issues
    }


def main():
    parser = argparse.ArgumentParser(
        description="Supply Chain Guardian - PyPI Static Scanner"
    )

    parser.add_argument(
        "package_path",
        help="Path to the extracted package directory"
    )

    parser.add_argument(
        "--output",
        default="reports/pypi-scan.json",
        help="Where to save the JSON report"
    )

    args = parser.parse_args()

    try:
        report = scan_directory(args.package_path)

    except (ValueError, OSError) as error:
        print(f"Scan failed: {error}", file=sys.stderr)
        raise SystemExit(1)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8"
    )

    print("\n========== SUPPLY CHAIN GUARDIAN ==========")
    print(f"Package:          {report['package']['name']}")
    print(f"Ecosystem:        {report['package']['ecosystem']}")
    print(f"Files discovered: {report['coverage']['files_discovered']}")
    print(f"Files analyzed:   {report['coverage']['files_analyzed']}")
    print(f"Files skipped:    {report['coverage']['files_skipped']}")
    print(f"Findings:         {len(report['findings'])}")
    print(f"Risk score:       {report['risk']['score']}/100")
    print(f"Severity:         {report['risk']['severity']}")
    print(f"Scan status:      {report['scan_status']}")
    print(f"Report:           {output_path}")
    print("============================================")


if __name__ == "__main__":
    main()
