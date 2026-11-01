import ast
import tokenize
from pathlib import Path

from .models import ParsedFile, ParseIssue

MAX_FILE_SIZE = 2 * 1024 * 1024


def parse_python_file(file_path, package_root):
    file_path = Path(file_path)
    package_root = Path(package_root).resolve()

    try:
        if file_path.is_symlink():
            return None, ParseIssue(str(file_path), "Symlink skipped")

        resolved = file_path.resolve()

        if not resolved.is_relative_to(package_root):
            return None, ParseIssue(str(file_path), "File outside package")

        if resolved.stat().st_size > MAX_FILE_SIZE:
            return None, ParseIssue(str(file_path), "File exceeds size limit")

        with tokenize.open(resolved) as file:
            source = file.read()

        tree = ast.parse(source, filename=str(resolved))

        parsed = ParsedFile(
            path=resolved.relative_to(package_root).as_posix(),
            source=source,
            tree=tree
        )

        return parsed, None

    except SyntaxError as error:
        return None, ParseIssue(
            str(file_path), error.msg, error.lineno
        )

    except (OSError, UnicodeError, ValueError) as error:
        return None, ParseIssue(str(file_path), str(error))