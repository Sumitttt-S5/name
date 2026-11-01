import argparse
import json
import re
import sys
import uuid
from pathlib import Path


SCANNER_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCANNER_DIR))


from scanner.file_discovery import discover_python_files
from scanner.parser import parse_python_file
from scanner.ast_analyzer import analyze_python_file
from scanner.taint_engine import analyze_taint
from scanner.name_detector import (
    analyze_package_name,
    normalize_package_name,
)
from scanner.package_metadata import inspect_package_metadata
from scanner.false_alarm_filter import assess_findings


def add_stage1_finding(
    findings,
    rule_id,
    title,
    description,
    evidence,
):
    """Add an evidence-only Stage 1 finding."""
    findings.append({
        "finding_id": f"SCG-STAGE1-{len(findings) + 1:03d}",
        "stage": 1,
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "file": None,
        "line": None,
        "evidence": evidence,
        "mitre_techniques": [],
        "score_contribution": 0,
    })


def inspect_readme_consistency(package_root, metadata_name, metadata_version):
    """
    Compare explicit README package identity and installation references
    against package metadata. README content is read as text, never executed.
    """
    readme_names = (
        "README.md",
        "README.rst",
        "README.txt",
        "README",
        "readme.md",
        "readme.rst",
        "readme.txt",
    )

    readme_path = None

    for filename in readme_names:
        candidate = package_root / filename

        try:
            if (
                candidate.is_file()
                and not candidate.is_symlink()
                and candidate.stat().st_size <= 1024 * 1024
            ):
                readme_path = candidate
                break
        except OSError:
            continue

    if readme_path is None:
        return {"found": False, "path": None, "evidence": []}

    try:
        content = readme_path.read_text(
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return {"found": False, "path": None, "evidence": []}

    evidence = []
    normalized_metadata_name = (
        normalize_package_name(metadata_name, "pypi")
        if metadata_name
        else None
    )

    # Check explicit pip installation commands.
    install_commands = re.findall(
        r"(?im)^\s*(?:\$?\s*)pip(?:3)?\s+install\s+([^\s\\]+)",
        content,
    )

    for command_name in install_commands:
        command_name = command_name.strip("'`").strip('"')

        if command_name.startswith("-"):
            continue

        command_name = re.split(
            r"[<>=!~\[]",
            command_name,
            maxsplit=1,
        )[0]

        if (
            normalized_metadata_name
            and command_name
            and normalize_package_name(command_name, "pypi")
            != normalized_metadata_name
        ):
            evidence.append(
                f"README installation command references '{command_name}', "
                f"while metadata declares '{metadata_name}'."
            )

    # Check explicit package-name declarations.
    declared_names = re.findall(
        r"(?im)^\s*(?:package\s+name|project\s+name)\s*:\s*([A-Za-z0-9_.-]+)",
        content,
    )

    for declared_name in declared_names:
        if (
            normalized_metadata_name
            and normalize_package_name(declared_name, "pypi")
            != normalized_metadata_name
        ):
            evidence.append(
                f"README declares package name '{declared_name}', "
                f"but metadata declares '{metadata_name}'."
            )

    # Version is intentionally not inferred from arbitrary prose.
    return {
        "found": True,
        "path": str(readme_path.relative_to(package_root)),
        "evidence": evidence,
    }


def calculate_severity(score):
    """Convert a numeric risk score into a severity label."""
    if score >= 65:
        return "CRITICAL"
    elif score >= 40:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    return "LOW"


def scan_directory(package_path, expected_package_name=None):
    package_root = Path(package_path).resolve()

    if not package_root.is_dir():
        raise ValueError(f"Package directory not found: {package_root}")

    # The expected name normally comes from the uploaded archive filename.
    archive_name = (
        expected_package_name.strip()
        if isinstance(expected_package_name, str)
        and expected_package_name.strip()
        else package_root.name
    )

    # Inspect package metadata without executing package code.
    metadata_result = inspect_package_metadata(package_root)

    metadata_name = metadata_result["name"]
    metadata_version = metadata_result["version"]

    # Prefer internal metadata for the reported package identity.
    package_name = metadata_name or archive_name

    python_files = discover_python_files(package_root)

    all_findings = []
    parse_issues = []
    analyzed_files = 0

    # ---------------------------------------------------------
    # STAGE 1: PACKAGE IDENTITY AND NAME ANALYSIS
    # ---------------------------------------------------------

    # Compare archive-derived and metadata-declared identities.
    if metadata_result["found"]:
        archive_normalized = normalize_package_name(
            archive_name,
            "pypi",
        )
        metadata_normalized = normalize_package_name(
            metadata_name,
            "pypi",
        )

        if archive_normalized != metadata_normalized:
            add_stage1_finding(
                all_findings,
                "SCG-PACKAGE-IDENTITY-MISMATCH",
                "Package filename and metadata identity mismatch",
                (
                    f"The archive-derived name '{archive_name}' differs "
                    f"from the internally declared package name "
                    f"'{metadata_name}'. Verify the package identity."
                ),
                [
                    f"Archive-derived name: {archive_name}",
                    f"Metadata-declared name: {metadata_name}",
                    f"Metadata source: {metadata_result['source']}",
                    "This mismatch is evidence, not proof of malicious intent.",
                ],
            )

    # Report conflicting identities declared by metadata files.
    if metadata_result["identity_conflict"]:
        identity_evidence = [
            (
                f"Declared name: {item['name']}; "
                f"version: {item['version']}; "
                f"source: {item['source']}"
            )
            for item in metadata_result["all_identities"]
        ]

        add_stage1_finding(
            all_findings,
            "SCG-METADATA-IDENTITY-CONFLICT",
            "Conflicting package metadata identities",
            (
                "Multiple metadata files declare different package "
                "names. The selected identity follows metadata priority, "
                "but the conflict requires manual verification."
            ),
            identity_evidence,
        )

    # Analyze both archive-derived and metadata-declared names.
    # This prevents a suspicious filename from being ignored when
    # the internal metadata declares a different name.
    names_to_analyze = []

    for candidate_name in (archive_name, metadata_name):
        if not candidate_name:
            continue

        if candidate_name not in names_to_analyze:
            names_to_analyze.append(candidate_name)

    name_match_count = 0
    seen_name_matches = set()

    for candidate_name in names_to_analyze:
        name_result = analyze_package_name(
            candidate_name,
            ecosystem="pypi",
        )

        for match in name_result["matches"]:
            match_key = (
                normalize_package_name(candidate_name, "pypi"),
                normalize_package_name(
                    match["reference_package"],
                    "pypi",
                ),
            )

            if match_key in seen_name_matches:
                continue

            seen_name_matches.add(match_key)
            name_match_count += 1

            add_stage1_finding(
                all_findings,
                "SCG-NAME-TYPOSQUATTING",
                "Potential package-name impersonation",
                (
                    f"Package name '{candidate_name}' resembles popular "
                    f"package '{match['reference_package']}'. "
                    f"{match['reason']}."
                ),
                [
                    f"Name being checked: {candidate_name}",
                    f"Similar package: {match['reference_package']}",
                    f"Similarity: {match['similarity']}%",
                    f"Edit distance: {match['edit_distance']}",
                    f"Character substitution: "
                    f"{match['character_substitution']}",
                ],
            )

    if metadata_result["found"]:
        metadata_summary = (
            f"Internal metadata identifies the package as "
            f"'{metadata_name}' version '{metadata_version}'."
        )
    else:
        metadata_summary = (
            "No supported internal package metadata was found. "
            "The archive-derived name is used."
        )

    stage1_summary = (
        f"{metadata_summary} "
        f"Name similarity matches: {name_match_count}. "
        f"Metadata identity conflict: "
        f"{metadata_result['identity_conflict']}."
    )
        # Compare explicit README identity/install references with metadata.
    readme_result = inspect_readme_consistency(
        package_root,
        metadata_name,
        metadata_version,
    )

    for evidence_item in readme_result["evidence"]:
        add_stage1_finding(
            all_findings,
            "SCG-README-METADATA-MISMATCH",
            "README and package metadata inconsistency",
            (
                "The README contains an explicit package identity or "
                "installation reference that differs from the internally "
                "declared metadata. Verify the documentation and package identity."
            ),
            [
                f"README file: {readme_result['path']}",
                evidence_item,
                "Documentation inconsistency is not proof of malicious intent.",
            ],
        )

    stage1_summary += (
        f" README analyzed: {readme_result['found']}. "
        f"README inconsistencies: {len(readme_result['evidence'])}."
    )

    # ---------------------------------------------------------
    # STAGE 2: AST ANALYSIS AND TAINT TRACKING
    # ---------------------------------------------------------

    for file_path in python_files:
        parsed, parse_issue = parse_python_file(
            file_path,
            package_root,
        )

        if parse_issue is not None:
            parse_issues.append({
                "file": parse_issue.file,
                "error": parse_issue.error,
                "line": parse_issue.line,
            })
            continue

        if parsed is None:
            continue

        analyzed_files += 1

        ast_findings = analyze_python_file(parsed)

        all_findings.extend(
            finding.to_dict()
            for finding in ast_findings
        )

        taint_findings = analyze_taint(
            parsed.tree,
            parsed.path,
        )

        all_findings.extend(
            finding.to_dict()
            for finding in taint_findings
        )

    # ---------------------------------------------------------
    # ORIGINAL PRELIMINARY RISK CALCULATION
    # ---------------------------------------------------------

    # Preserve the original risk calculation for compatibility.
    score = min(
        100,
        sum(
            finding.get("score_contribution", 0)
            for finding in all_findings
        ),
    )

    severity = calculate_severity(score)

    # Stage 1 evidence-only findings do not establish risk confidence.
    score_bearing_findings = [
        finding
        for finding in all_findings
        if finding.get("score_contribution", 0) > 0
    ]

    risk_confidence = (
        "MEDIUM"
        if score_bearing_findings
        else "UNKNOWN"
    )

    # ---------------------------------------------------------
    # STAGE 5: FALSE-ALARM FILTER AND FINDING CORRELATION
    # ---------------------------------------------------------

    # Assess the findings produced by Stages 1 and 2.
    # The original findings remain unchanged.
    stage5_result = assess_findings(all_findings)

    context_adjusted_score = stage5_result["risk"]["score"]

    context_adjusted_severity = calculate_severity(
        context_adjusted_score
    )

    stage5_summary_data = stage5_result["summary"]

    stage5_summary = (
        "False-alarm assessment completed. "
        f"{stage5_summary_data['unique_findings']} unique findings retained; "
        f"{stage5_summary_data['duplicates_removed']} duplicates removed; "
        f"{stage5_summary_data['suspicious_findings']} suspicious findings; "
        f"{stage5_summary_data['needs_review']} findings requiring review."
    )

    scan_status = "PARTIAL" if parse_issues else "COMPLETED"

    # ---------------------------------------------------------
    # FINAL SCAN REPORT
    # ---------------------------------------------------------

    report = {
        "schema_version": "1.0.0",
        "scan_id": str(uuid.uuid4()),

        "package": {
            "name": package_name,
            "version": metadata_version,
            "ecosystem": "pypi",
            "artifact_hash": None,
            "artifact_filename": None,
        },

        "scan_status": scan_status,

        "risk": {
            # Original risk calculation, preserved for compatibility.
            "score": score,
            "severity": severity,
            "confidence": risk_confidence,

            # Separate Stage 5 context-adjusted assessment.
            "context_adjusted_score": context_adjusted_score,
            "context_adjusted_severity": context_adjusted_severity,

            "explanation": (
                "The original risk score is calculated from static "
                "code indicators. The context-adjusted score is "
                "calculated separately by Stage 5 using finding "
                "classification, confidence, evidence and duplicate "
                "filtering. Neither score is a verified malware verdict."
            ),
        },

        "coverage": {
            "files_discovered": len(python_files),
            "files_analyzed": analyzed_files,
            "files_skipped": len(parse_issues),
            "limitations": [
                "README consistency checks cover explicit package-name and pip-install references only.",
                "README version claims and general-purpose documentation claims are not semantically validated.",
                "Only Python source files were analyzed.",
                "Taint analysis has limited control-flow coverage.",
                "Cross-function taint propagation is not implemented.",
                "Previous package versions were not compared.",
                "Dynamic sandbox analysis was not performed by this scan.",
                "Package-name comparison uses a limited local reference list.",
                "Metadata identity is based on supported static metadata files.",
                "Dynamic or externally resolved package metadata is not evaluated.",
                "Stage 5 uses experimental heuristic classification, not a calibrated probability.",
                "Stage 5 does not yet correlate static findings with Stage 4 runtime sandbox events.",
            ],
        },

        "stages": {
            "stage_1_name_and_lie_detector": {
                "status": "COMPLETED",
                "summary": stage1_summary,
            },

            "stage_2_password_and_gibberish_tracker": {
                "status": "PARTIAL",
                "summary": (
                    "Python AST indicators and basic source-to-sink "
                    "taint analysis performed."
                ),
            },

            "stage_3_update_hijack_detector": {
                "status": "NOT_AVAILABLE",
                "summary": "Previous version comparison is available through a separate endpoint, but is not integrated into this scan workflow.",
            },

            "stage_4_fake_bait_sandbox": {
                "status": "NOT_AVAILABLE",
                "summary": "Dynamic sandbox execution is available through a separate endpoint, but is not integrated into this scan workflow.",
            },

            "stage_5_false_alarm_filter": {
                "status": "COMPLETED",
                "summary": stage5_summary,
            },

            "stage_6_ai_reporter": {
                "status": "NOT_AVAILABLE",
                "summary": "AI explanation and SARIF export not implemented.",
            },
        },

        "findings": all_findings,

        # Complete Stage 5 output, including classified findings,
        # duplicate information, correlations and adjusted risk.
        "false_alarm_filter": stage5_result,

        "parse_issues": parse_issues,
    }

    return report
    def main():
        parser = argparse.ArgumentParser(
            description="Supply Chain Guardian - Python Package Scanner"
        )

        parser.add_argument(
            "package_path",
            help="Path to the extracted Python package directory",
        )

        parser.add_argument(
            "--output",
            default="reports/pypi-scan.json",
            help="Path for the JSON scan report",
        )

        args = parser.parse_args()

        try:
            report = scan_directory(args.package_path)

            output_path = Path(args.output)
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with output_path.open("w", encoding="utf-8") as file:
                json.dump(report, file, indent=4)

            print("\n========== SUPPLY CHAIN GUARDIAN ==========")
            print(f"Package:                  {report['package']['name']}")
            print(f"Ecosystem:                pypi")
            print(f"Files discovered:         {report['coverage']['files_discovered']}")
            print(f"Files analyzed:           {report['coverage']['files_analyzed']}")
            print(f"Files skipped:            {report['coverage']['files_skipped']}")
            print(f"Findings:                 {len(report['findings'])}")
            print(f"Original risk score:      {report['risk']['score']}/100")
            print(f"Original severity:        {report['risk']['severity']}")
            print(
                "Adjusted risk score:      "
                f"{report['risk']['context_adjusted_score']}/100"
            )
            print(
                "Adjusted severity:        "
                f"{report['risk']['context_adjusted_severity']}"
            )
            print(f"Scan status:              {report['scan_status']}")
            print(
                "Stage 1:                  "
                f"{report['stages']['stage_1_name_and_lie_detector']['status']}"
            )
            print(
                "Stage 5:                  "
                f"{report['stages']['stage_5_false_alarm_filter']['status']}"
            )
            print(f"Report:                   {output_path}")
            print("============================================\n")

        except (ValueError, OSError, FileNotFoundError) as error:
            print(f"Scan failed: {error}", file=sys.stderr)
            sys.exit(1)


    if __name__ == "__main__":
        main()