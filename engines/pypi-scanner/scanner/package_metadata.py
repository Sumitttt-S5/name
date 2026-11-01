
import configparser
import email
import email.policy
import re
import tomllib
from pathlib import Path
from typing import Any


MAX_METADATA_SIZE = 2 * 1024 * 1024
MAX_METADATA_FILES = 100


def normalize_identity(name: str) -> str:
    """Normalize a package name for identity comparison."""
    return re.sub(r"[-_.]+", "-", name).casefold().strip()


def _read_text(path: Path) -> str | None:
    """Read a small metadata file without executing package code."""
    try:
        if path.is_symlink() or not path.is_file():
            return None

        if path.stat().st_size > MAX_METADATA_SIZE:
            return None

        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def _read_email_metadata(path: Path) -> dict[str, Any] | None:
    content = _read_text(path)
    if content is None:
        return None

    try:
        message = email.message_from_string(
            content,
            policy=email.policy.default,
        )

        name = message.get("Name")
        version = message.get("Version")

        if not name or not str(name).strip():
            return None

        return {
            "name": str(name).strip(),
            "version": str(version).strip() if version else None,
            "source": str(path),
            "format": "email-metadata",
        }
    except (ValueError, TypeError):
        return None


def _read_setup_cfg(path: Path) -> dict[str, Any] | None:
    content = _read_text(path)
    if content is None:
        return None

    parser = configparser.ConfigParser()

    try:
        parser.read_string(content)

        if not parser.has_section("metadata"):
            return None

        section = parser["metadata"]
        name = section.get("name")

        if not name or not name.strip():
            return None

        version = section.get("version")

        return {
            "name": name.strip(),
            "version": version.strip() if version else None,
            "source": str(path),
            "format": "setup.cfg",
        }
    except (configparser.Error, ValueError):
        return None


def _read_pyproject(path: Path) -> dict[str, Any] | None:
    content = _read_text(path)
    if content is None:
        return None

    try:
        data = tomllib.loads(content)
        project = data.get("project", {})

        if not isinstance(project, dict):
            return None

        name = project.get("name")
        version = project.get("version")

        # Dynamic project names cannot safely be resolved here.
        if not isinstance(name, str) or not name.strip():
            return None

        if version is not None and not isinstance(version, str):
            return None

        return {
            "name": name.strip(),
            "version": version.strip() if version else None,
            "source": str(path),
            "format": "pyproject.toml",
        }
    except (tomllib.TOMLDecodeError, AttributeError, TypeError):
        return None


def _collect_candidates(root: Path) -> list[tuple[int, Path]]:
    """Find supported metadata files within the package directory."""
    candidates = []

    patterns = [
        (0, "*.dist-info/METADATA"),
        (1, "PKG-INFO"),
        (2, "pyproject.toml"),
        (3, "setup.cfg"),
    ]

    for priority, pattern in patterns:
        for path in root.rglob(pattern):
            try:
                relative_parts = path.relative_to(root).parts

                if len(relative_parts) > 5:
                    continue

                if path.is_symlink():
                    continue

                candidates.append((priority, path))

                if len(candidates) >= MAX_METADATA_FILES:
                    return candidates

            except (OSError, ValueError):
                continue

    candidates.sort(key=lambda item: (item[0], str(item[1])))
    return candidates


def inspect_package_metadata(package_root: Path) -> dict[str, Any]:
    """
    Inspect package metadata without importing or executing package code.

    All valid identities are collected. The highest-priority identity is
    selected, while conflicting names are reported separately.
    """
    root = Path(package_root).resolve()

    if not root.is_dir():
        raise ValueError("Package root must be an existing directory.")

    candidates = _collect_candidates(root)
    identities = []

    for priority, path in candidates:
        if priority in (0, 1):
            metadata = _read_email_metadata(path)
        elif priority == 2:
            metadata = _read_pyproject(path)
        else:
            metadata = _read_setup_cfg(path)

        if metadata:
            metadata["priority"] = priority
            identities.append(metadata)

    if not identities:
        return {
            "found": False,
            "name": None,
            "version": None,
            "source": None,
            "all_identities": [],
            "identity_conflict": False,
        }

    identities.sort(
        key=lambda item: (
            item["priority"],
            item["source"],
        )
    )

    selected = identities[0]

    distinct_names = {
        normalize_identity(item["name"])
        for item in identities
    }

    return {
        "found": True,
        "name": selected["name"],
        "version": selected["version"],
        "source": selected["source"],
        "all_identities": identities,
        "identity_conflict": len(distinct_names) > 1,
    }
