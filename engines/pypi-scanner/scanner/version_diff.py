
import ast
import hashlib
import json
from pathlib import Path
from collections import Counter

from .file_discovery import discover_python_files
from .parser import parse_python_file
from .ast_analyzer import analyze_python_file
from .taint_engine import analyze_taint


# Security-relevant findings that Stage 3 tracks.
TRACKED_RULES = {
    "PY-DYNAMIC-001",
    "PY-PROCESS-001",
    "PY-PROCESS-002",
    "PY-NETWORK-001",
    "PY-SECRET-SOURCE-001",
    "PY-OBFUSCATION-001",
    "PY-TAINT-EXFIL-001",
}


# Installation and build configuration files.
INSTALLATION_FILES = (
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
)


def calculate_directory_hash(package_root):
    """Calculate a deterministic SHA-256 hash of package files."""
    root = Path(package_root).resolve()

    if not root.is_dir():
        raise ValueError(f"Package directory does not exist: {root}")

    digest = hashlib.sha256()

    files = sorted(
        path for path in root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and not any(
            part in {
                ".git", ".venv", "venv", "__pycache__",
                "node_modules", "build", "dist"
            }
            for part in path.relative_to(root).parts
        )
    )

    for file_path in files:
        relative_path = file_path.relative_to(root).as_posix()

        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")

        with file_path.open("rb") as file:
            while chunk := file.read(1024 * 1024):
                digest.update(chunk)

        digest.update(b"\0")

    return digest.hexdigest()


def normalize_finding(finding):
    """
    Create a stable fingerprint independent of line number,
    finding ID and absolute file path.
    """
    rule_id = finding.rule_id

    if rule_id not in TRACKED_RULES:
        return None

    evidence = " ".join(finding.evidence).strip().lower()

    normalized = {
        "rule_id": rule_id,
        "title": finding.title.strip().lower(),
        "evidence": evidence,
    }

    fingerprint_input = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
    )

    fingerprint = hashlib.sha256(
        fingerprint_input.encode("utf-8")
    ).hexdigest()

    return {
        "fingerprint": fingerprint,
        "rule_id": rule_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "description": finding.description,
        "evidence": list(finding.evidence),
        "file": finding.file,
        "line": finding.line,
        "score_contribution": finding.score_contribution,
    }


def analyze_package_version(package_root):
    """Run existing static and taint analysis on a package directory."""
    root = Path(package_root).resolve()

    if not root.is_dir():
        raise ValueError(f"Package directory does not exist: {root}")

    findings = []
    parse_issues = []
    files = discover_python_files(root)

    for file_path in files:
        parsed_file, issue = parse_python_file(file_path, root)

        if issue:
            parse_issues.append({
                "file": issue.file,
                "error": issue.error,
                "line": issue.line,
            })
            continue

        findings.extend(analyze_python_file(parsed_file))
        findings.extend(
            analyze_taint(parsed_file.tree, parsed_file.path)
        )

    normalized = []

    for finding in findings:
        item = normalize_finding(finding)

        if item:
            normalized.append(item)

    return {
        "package_hash": calculate_directory_hash(root),
        "files_discovered": len(files),
        "files_analyzed": len(files) - len(parse_issues),
        "parse_issues": parse_issues,
        "findings": normalized,
    }


def compare_installation_files(baseline_path, candidate_path):
    """
    Detect changes to package installation configuration files.

    Reports added, removed and modified files. A change is not
    automatically considered malicious.
    """
    baseline_root = Path(baseline_path).resolve()
    candidate_root = Path(candidate_path).resolve()

    changes = []

    for filename in INSTALLATION_FILES:
        old_file = baseline_root / filename
        new_file = candidate_root / filename

        old_exists = old_file.is_file() and not old_file.is_symlink()
        new_exists = new_file.is_file() and not new_file.is_symlink()

        if not old_exists and not new_exists:
            continue

        old_hash = None
        new_hash = None

        try:
            if old_exists:
                old_digest = hashlib.sha256()

                with old_file.open("rb") as file:
                    while chunk := file.read(1024 * 1024):
                        old_digest.update(chunk)

                old_hash = old_digest.hexdigest()

            if new_exists:
                new_digest = hashlib.sha256()

                with new_file.open("rb") as file:
                    while chunk := file.read(1024 * 1024):
                        new_digest.update(chunk)

                new_hash = new_digest.hexdigest()

        except OSError:
            continue

        if old_hash != new_hash:
            if not old_exists:
                change_type = "ADDED"
            elif not new_exists:
                change_type = "REMOVED"
            else:
                change_type = "MODIFIED"

            changes.append({
                "file": filename,
                "change": change_type,
                "baseline_hash": old_hash,
                "candidate_hash": new_hash,
                "requires_review": True,
                "description": (
                    "Installation configuration changed between "
                    "the compared package versions. Review the change "
                    "for new build or installation behaviour."
                ),
            })

    return changes


def compare_versions(
    baseline_path,
    candidate_path,
    baseline_version,
    candidate_version,
):
    """
    Compare two versions of a Python package.

    Newly introduced findings are reported separately from
    findings that existed in the baseline.
    """
    if not baseline_version or not candidate_version:
        raise ValueError("Both package versions must be provided.")

    baseline = analyze_package_version(baseline_path)
    candidate = analyze_package_version(candidate_path)

    # Compare installation and build configuration files.
    installation_changes = compare_installation_files(
        baseline_path,
        candidate_path,
    )

    baseline_counts = Counter(
        item["fingerprint"] for item in baseline["findings"]
    )

    candidate_counts = Counter(
        item["fingerprint"] for item in candidate["findings"]
    )

    baseline_lookup = {
        item["fingerprint"]: item
        for item in baseline["findings"]
    }

    candidate_lookup = {
        item["fingerprint"]: item
        for item in candidate["findings"]
    }

    introduced = []
    removed = []
    persistent = []

    for fingerprint, count in candidate_counts.items():
        old_count = baseline_counts.get(fingerprint, 0)

        if count > old_count:
            introduced.extend(
                [candidate_lookup[fingerprint]]
                * (count - old_count)
            )

        if old_count > 0:
            persistent.extend(
                [candidate_lookup[fingerprint]]
                * min(count, old_count)
            )

    for fingerprint, count in baseline_counts.items():
        new_count = candidate_counts.get(fingerprint, 0)

        if count > new_count:
            removed.extend(
                [baseline_lookup[fingerprint]]
                * (count - new_count)
            )

    comparison_complete = (
        not baseline["parse_issues"]
        and not candidate["parse_issues"]
    )

    return {
        "stage": 3,
        "stage_name": "Update Hijack Detector",
        "status": (
            "COMPLETED" if comparison_complete else "PARTIAL"
        ),

        "baseline": {
            "version": baseline_version,
            "artifact_hash": baseline["package_hash"],
            "files_discovered": baseline["files_discovered"],
            "files_analyzed": baseline["files_analyzed"],
        },

        "candidate": {
            "version": candidate_version,
            "artifact_hash": candidate["package_hash"],
            "files_discovered": candidate["files_discovered"],
            "files_analyzed": candidate["files_analyzed"],
        },

        "summary": {
            "introduced_behaviours": len(introduced),
            "removed_behaviours": len(removed),
            "persistent_behaviours": len(persistent),
            "installation_files_changed": len(installation_changes),
        },

        "introduced_behaviours": introduced,
        "removed_behaviours": removed,
        "persistent_behaviours": persistent,

        "installation_changes": installation_changes,

        "limitations": [
            "Only Python source files are analyzed.",
            "The comparison inherits the limitations of the existing AST and taint analyzers.",
            "The taint analyzer does not perform full interprocedural or control-flow analysis.",
            "A newly introduced capability is not proof of malicious intent.",
            "Fingerprint matching uses rule, title and evidence; semantic equivalence is not guaranteed.",
            "Installation-file comparison detects changes but does not determine whether those changes are malicious.",
        ],

        "parse_issues": {
            "baseline": baseline["parse_issues"],
            "candidate": candidate["parse_issues"],
        },
    }
