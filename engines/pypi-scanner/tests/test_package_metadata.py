
from pathlib import Path
import sys

SCANNER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCANNER_DIR))

from scanner.package_metadata import inspect_package_metadata


def test_reads_wheel_metadata(tmp_path):
    metadata_dir = tmp_path / "demo-1.0.dist-info"
    metadata_dir.mkdir()

    (metadata_dir / "METADATA").write_text(
        "Metadata-Version: 2.1\n"
        "Name: demo-package\n"
        "Version: 1.0\n\n",
        encoding="utf-8",
    )

    result = inspect_package_metadata(tmp_path)

    assert result["found"] is True
    assert result["name"] == "demo-package"
    assert result["version"] == "1.0"


def test_reads_source_distribution_metadata(tmp_path):
    (tmp_path / "PKG-INFO").write_text(
        "Metadata-Version: 2.1\n"
        "Name: sample-project\n"
        "Version: 2.5.0\n\n",
        encoding="utf-8",
    )

    result = inspect_package_metadata(tmp_path)

    assert result["found"] is True
    assert result["name"] == "sample-project"
    assert result["version"] == "2.5.0"


def test_reads_pyproject_metadata(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "toml-project"\nversion = "1.2.0"\n',
        encoding="utf-8",
    )

    result = inspect_package_metadata(tmp_path)

    assert result["found"] is True
    assert result["name"] == "toml-project"
    assert result["version"] == "1.2.0"


def test_returns_not_found_when_metadata_missing(tmp_path):
    result = inspect_package_metadata(tmp_path)

    assert result["found"] is False
    assert result["name"] is None


def test_does_not_execute_setup_py(tmp_path):
    marker = tmp_path / "executed.txt"

    (tmp_path / "setup.py").write_text(
        f"from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )

    inspect_package_metadata(tmp_path)

    assert not marker.exists()


def test_detects_conflicting_metadata_identities(tmp_path):
    wheel_metadata = tmp_path / "demo-1.0.dist-info"
    wheel_metadata.mkdir()

    (wheel_metadata / "METADATA").write_text(
        "Metadata-Version: 2.1\n"
        "Name: demo-package\n"
        "Version: 1.0\n\n",
        encoding="utf-8",
    )

    other_metadata = tmp_path / "source" / "PKG-INFO"
    other_metadata.parent.mkdir()

    other_metadata.write_text(
        "Metadata-Version: 2.1\n"
        "Name: different-package\n"
        "Version: 1.0\n\n",
        encoding="utf-8",
    )

    result = inspect_package_metadata(tmp_path)

    assert result["found"] is True
    assert result["name"] == "demo-package"
    assert result["identity_conflict"] is True
    assert len(result["all_identities"]) == 2


def test_equivalent_names_do_not_create_conflict(tmp_path):
    metadata_dir = tmp_path / "demo-1.0.dist-info"
    metadata_dir.mkdir()

    (metadata_dir / "METADATA").write_text(
        "Metadata-Version: 2.1\n"
        "Name: my-package\n"
        "Version: 1.0\n\n",
        encoding="utf-8",
    )

    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "my_package"\nversion = "1.0"\n',
        encoding="utf-8",
    )

    result = inspect_package_metadata(tmp_path)

    assert result["found"] is True
    assert result["identity_conflict"] is False
    assert len(result["all_identities"]) == 2

