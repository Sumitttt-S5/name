import os
from pathlib import Path

SKIP_DIRECTORIES = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", ".tox", "build", "dist"
}


def discover_python_files(root):
    root = Path(root).resolve()

    if not root.exists() or not root.is_dir():
        raise ValueError(f"Invalid package directory: {root}")

    discovered = []

    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)

        directories[:] = [
            name for name in directories
            if name not in SKIP_DIRECTORIES
            and not (current_path / name).is_symlink()
        ]

        for filename in filenames:
            file_path = current_path / filename

            if filename.endswith(".py") and not file_path.is_symlink():
                discovered.append(file_path)

    return sorted(discovered)