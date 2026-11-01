
import shutil
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILES = 3000
MAX_TOTAL_SIZE = 250 * 1024 * 1024
MAX_FILE_SIZE = 20 * 1024 * 1024


def safe_member_path(destination: Path, member_name: str) -> Path:
    normalized = member_name.replace("\\", "/")
    member = PurePosixPath(normalized)

    if (
        member.is_absolute()
        or ".." in member.parts
        or not member.parts
        or ":" in normalized
    ):
        raise ValueError(f"Unsafe archive path: {member_name}")

    target = destination.joinpath(*member.parts).resolve()

    if not target.is_relative_to(destination.resolve()):
        raise ValueError(f"Archive path escapes destination: {member_name}")

    return target


def extract_zip(archive: Path, destination: Path):
    total_size = 0
    file_count = 0

    with zipfile.ZipFile(archive) as package:
        members = package.infolist()

        if len(members) > MAX_FILES:
            raise ValueError("Archive contains too many files.")

        for member in members:
            target = safe_member_path(destination, member.filename)

            mode = (member.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError("Symbolic links are not allowed.")

            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            if member.file_size > MAX_FILE_SIZE:
                raise ValueError("An archive file exceeds the size limit.")

            total_size += member.file_size
            file_count += 1

            if file_count > MAX_FILES or total_size > MAX_TOTAL_SIZE:
                raise ValueError("Archive extraction limits exceeded.")

            target.parent.mkdir(parents=True, exist_ok=True)

            copied = 0

            with package.open(member) as source, target.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break

                    copied += len(chunk)

                    if copied > MAX_FILE_SIZE:
                        raise ValueError("Extracted file exceeds size limit.")

                    output.write(chunk)

            if copied != member.file_size:
                raise ValueError("Archive file size mismatch.")


def extract_tar(archive: Path, destination: Path):
    total_size = 0
    file_count = 0

    with tarfile.open(archive, mode="r:gz") as package:
        members = package.getmembers()

        if len(members) > MAX_FILES:
            raise ValueError("Archive contains too many entries.")

        for member in members:
            target = safe_member_path(destination, member.name)

            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            if not member.isfile():
                raise ValueError(
                    f"Unsupported archive entry type: {member.name}"
                )

            if member.size > MAX_FILE_SIZE:
                raise ValueError("An archive file exceeds the size limit.")

            total_size += member.size
            file_count += 1

            if file_count > MAX_FILES or total_size > MAX_TOTAL_SIZE:
                raise ValueError("Archive extraction limits exceeded.")

            target.parent.mkdir(parents=True, exist_ok=True)

            source = package.extractfile(member)

            if source is None:
                raise ValueError(f"Cannot read archive file: {member.name}")

            copied = 0

            with source, target.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break

                    copied += len(chunk)

                    if copied > MAX_FILE_SIZE:
                        raise ValueError("Extracted file exceeds size limit.")

                    output.write(chunk)

            if copied != member.size:
                raise ValueError("Extracted file size mismatch.")


def extract_archive(archive_path: Path, destination: Path):
    archive_path = Path(archive_path)
    destination = Path(destination)

    destination.mkdir(parents=True, exist_ok=True)

    if zipfile.is_zipfile(archive_path):
        extract_zip(archive_path, destination)

    elif tarfile.is_tarfile(archive_path):
        extract_tar(archive_path, destination)

    else:
        raise ValueError(
            "Unsupported or invalid archive. "
            "Upload a .whl, .zip, .tar.gz or .tgz package."
        )

    return destination
