
from pathlib import Path
import sys

SCANNER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCANNER_DIR))

from run_scan import scan_directory


def create_metadata(root, name, version="1.0"):
    metadata_dir = root / "demo-1.0.dist-info"
    metadata_dir.mkdir(parents=True, exist_ok=True)

    (metadata_dir / "METADATA").write_text(
        "Metadata-Version: 2.1\n"
        f"Name: {name}\n"
        f"Version: {version}\n\n",
        encoding="utf-8",
    )


def test_matching_archive_and_metadata_identity(tmp_path):
    package_dir = tmp_path / "my-project"
    package_dir.mkdir()

    create_metadata(package_dir, "my-project")

    report = scan_directory(package_dir)

    mismatch_findings = [
        finding for finding in report["findings"]
        if finding["rule_id"] == "SCG-PACKAGE-IDENTITY-MISMATCH"
    ]

    assert report["package"]["name"] == "my-project"
    assert mismatch_findings == []


def test_detects_archive_metadata_name_mismatch(tmp_path):
    package_dir = tmp_path / "requests"
    package_dir.mkdir()

    create_metadata(package_dir, "different-package")

    report = scan_directory(package_dir)

    mismatch_findings = [
        finding for finding in report["findings"]
        if finding["rule_id"] == "SCG-PACKAGE-IDENTITY-MISMATCH"
    ]

    assert len(mismatch_findings) == 1
    assert mismatch_findings[0]["score_contribution"] == 0


def test_detects_conflicting_internal_metadata(tmp_path):
    package_dir = tmp_path / "demo"
    package_dir.mkdir()

    create_metadata(package_dir, "demo")

    other_metadata = package_dir / "source" / "PKG-INFO"
    other_metadata.parent.mkdir()

    other_metadata.write_text(
        "Metadata-Version: 2.1\n"
        "Name: different-project\n"
        "Version: 1.0\n\n",
        encoding="utf-8",
    )

    report = scan_directory(package_dir)

    conflict_findings = [
        finding for finding in report["findings"]
        if finding["rule_id"] == "SCG-METADATA-IDENTITY-CONFLICT"
    ]

    assert len(conflict_findings) == 1
    assert conflict_findings[0]["score_contribution"] == 0


def test_name_findings_do_not_increase_risk_score(tmp_path):
    package_dir = tmp_path / "reqeusts"
    package_dir.mkdir()

    create_metadata(package_dir, "reqeusts")

    report = scan_directory(package_dir)

    name_findings = [
        finding for finding in report["findings"]
        if finding["stage"] == 1
    ]

    assert len(name_findings) >= 1
    assert all(
        finding["score_contribution"] == 0
        for finding in name_findings
    )
