import sys
from pathlib import Path
import pytest

SCANNER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCANNER_ROOT))
from scanner.version_diff import (
    calculate_directory_hash,
    compare_versions,
)


def create_package(root, filename, code):
    root.mkdir(parents=True, exist_ok=True)
    (root / filename).write_text(code, encoding="utf-8")
    return root


def compare(old_dir, new_dir):
    return compare_versions(
        baseline_path=old_dir,
        candidate_path=new_dir,
        baseline_version="1.0.0",
        candidate_version="1.1.0",
    )


def test_detects_new_process_execution(tmp_path):
    old_dir = create_package(
        tmp_path / "old",
        "main.py",
        "print('Hello world')\n",
    )

    new_dir = create_package(
        tmp_path / "new",
        "main.py",
        "import os\nos.system('whoami')\n",
    )

    result = compare(old_dir, new_dir)

    introduced_rules = {
        item["rule_id"]
        for item in result["introduced_behaviours"]
    }

    assert "PY-PROCESS-001" in introduced_rules
    assert result["summary"]["introduced_behaviours"] >= 1


def test_detects_removed_behaviour(tmp_path):
    old_dir = create_package(
        tmp_path / "old",
        "main.py",
        "import os\nos.system('whoami')\n",
    )

    new_dir = create_package(
        tmp_path / "new",
        "main.py",
        "print('Hello world')\n",
    )

    result = compare(old_dir, new_dir)

    removed_rules = {
        item["rule_id"]
        for item in result["removed_behaviours"]
    }

    assert "PY-PROCESS-001" in removed_rules


def test_detects_persistent_behaviour(tmp_path):
    old_dir = create_package(
        tmp_path / "old",
        "main.py",
        "import requests\nrequests.get('https://example.com')\n",
    )

    new_dir = create_package(
        tmp_path / "new",
        "main.py",
        "import requests\nrequests.get('https://example.com')\n",
    )

    result = compare(old_dir, new_dir)

    persistent_rules = {
        item["rule_id"]
        for item in result["persistent_behaviours"]
    }

    assert "PY-NETWORK-001" in persistent_rules
    assert result["summary"]["introduced_behaviours"] == 0
    assert result["summary"]["removed_behaviours"] == 0


def test_unchanged_safe_package_has_no_changes(tmp_path):
    old_dir = create_package(
        tmp_path / "old",
        "main.py",
        "def hello():\n    return 'hello'\n",
    )

    new_dir = create_package(
        tmp_path / "new",
        "main.py",
        "def hello():\n    return 'hello'\n",
    )

    result = compare(old_dir, new_dir)

    assert result["summary"]["introduced_behaviours"] == 0
    assert result["summary"]["removed_behaviours"] == 0
    assert result["summary"]["persistent_behaviours"] == 0


def test_calculates_different_hashes_for_different_packages(tmp_path):
    old_dir = create_package(
        tmp_path / "old",
        "main.py",
        "print('old version')\n",
    )

    new_dir = create_package(
        tmp_path / "new",
        "main.py",
        "print('new version')\n",
    )

    old_hash = calculate_directory_hash(old_dir)
    new_hash = calculate_directory_hash(new_dir)

    assert len(old_hash) == 64
    assert len(new_hash) == 64
    assert old_hash != new_hash


def test_identical_packages_have_identical_hashes(tmp_path):
    old_dir = create_package(
        tmp_path / "old",
        "main.py",
        "print('same package')\n",
    )

    new_dir = create_package(
        tmp_path / "new",
        "main.py",
        "print('same package')\n",
    )

    assert calculate_directory_hash(old_dir) == calculate_directory_hash(new_dir)


def test_invalid_package_directory_is_rejected(tmp_path):
    import pytest

    with pytest.raises(ValueError):
        calculate_directory_hash(tmp_path / "does-not-exist")


def test_missing_version_is_rejected(tmp_path):
    old_dir = create_package(
        tmp_path / "old",
        "main.py",
        "print('old')\n",
    )

    new_dir = create_package(
        tmp_path / "new",
        "main.py",
        "print('new')\n",
    )

    with pytest.raises(ValueError):
        compare_versions(old_dir, new_dir, "1.0.0", "")
def test_detects_changed_installation_configuration(tmp_path):
    old_dir = create_package(
        tmp_path / "old",
        "main.py",
        "print('hello')\n",
    )

    new_dir = create_package(
        tmp_path / "new",
        "main.py",
        "print('hello')\n",
    )

    (old_dir / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='demo')\n",
        encoding="utf-8",
    )

    (new_dir / "setup.py").write_text(
        "from setuptools import setup\n"
        "setup(name='demo', cmdclass={})\n",
        encoding="utf-8",
    )

    result = compare(old_dir, new_dir)

    assert len(result["installation_changes"]) == 1
    assert result["installation_changes"][0]["file"] == "setup.py"
    assert result["installation_changes"][0]["change"] == "MODIFIED"
    assert result["summary"]["installation_files_changed"] == 1