
import re
import sys
import tempfile
import tarfile
import zipfile

from pathlib import Path

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    Form,
    HTTPException,
)

from fastapi.middleware.cors import CORSMiddleware
from starlette.concurrency import run_in_threadpool


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCANNER_DIR = PROJECT_ROOT / "engines" / "pypi-scanner"

sys.path.insert(0, str(SCANNER_DIR))

from run_scan import scan_directory

from scanner.version_diff import compare_versions

from scanner.package_metadata import (
    inspect_package_metadata,
    normalize_identity,
)

from app.services.archive_service import extract_archive

from app.services.sandbox_service import run_sandbox
from scanner.false_alarm_filter import assess_findings

from app.services.runtime_correlation import (
    prepare_unified_findings,
)

MAX_UPLOAD_SIZE = 50 * 1024 * 1024

ALLOWED_EXTENSIONS = (
    ".whl",
    ".zip",
    ".tar.gz",
    ".tgz",
)


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Supply Chain Guardian API",
    description=(
        "AI-assisted software supply-chain security analysis "
        "for Python and JavaScript packages."
    ),
    version="1.0.0",
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# PACKAGE UTILITIES
# ============================================================

def get_package_name(filename: str) -> str:
    """
    Derive package name from an uploaded archive filename.
    """

    lower_name = filename.lower()

    extension = next(
        (
            ext for ext in ALLOWED_EXTENSIONS
            if lower_name.endswith(ext)
        ),
        None,
    )

    if extension is None:
        raise ValueError("Unsupported archive extension.")

    stem = filename[:-len(extension)]

    # Common Python package archive format:
    # package-name-1.0.0
    match = re.match(r"^(.+?)-(?=\d)", stem)

    name = match.group(1) if match else stem

    name = name.strip(" ._-")

    if not name:
        raise ValueError("Could not determine package name.")

    return name


async def save_upload(
    upload: UploadFile,
    destination: Path,
):
    """
    Save uploaded archive while enforcing the upload limit.
    """

    total_size = 0

    with destination.open("wb") as output:

        while True:

            chunk = await upload.read(1024 * 1024)

            if not chunk:
                break

            total_size += len(chunk)

            if total_size > MAX_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail="Upload exceeds the 50 MB limit.",
                )

            output.write(chunk)

    if total_size == 0:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty.",
        )


def validate_package_metadata(
    metadata: dict,
    expected_name: str,
):
    """
    Verify that archive metadata matches the expected package name.
    """

    if metadata["identity_conflict"]:
        raise ValueError(
            "Conflicting package identities found in archive metadata."
        )

    if metadata["found"]:

        actual_name = metadata.get("name")

        if (
            not actual_name
            or normalize_identity(actual_name)
            != normalize_identity(expected_name)
        ):
            raise ValueError(
                "Archive filename and package metadata identity do not match."
            )


# ============================================================
# ROOT ENDPOINT
# ============================================================

@app.get("/")
async def root():

    return {
        "application": "Supply Chain Guardian",
        "status": "running",
        "version": "1.0.0",
        "ecosystem": "PyPI",
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
async def health():

    return {
        "status": "healthy",
        "scanner": "python",
        "version": "1.0.0",
    }


# ============================================================
# STAGE 1 + STAGE 2
# PYPI PACKAGE SECURITY SCANNER
# ============================================================

@app.post("/api/scan")
async def scan_package(
    file: UploadFile = File(...),
):

    filename = Path(file.filename or "").name

    if not filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided.",
        )

    try:

        package_name = get_package_name(filename)

        with tempfile.TemporaryDirectory(
            prefix="scg_scan_"
        ) as temporary_directory:

            temporary_root = Path(temporary_directory)

            archive_path = temporary_root / "uploaded_package"

            extraction_directory = temporary_root / "extracted"

            # Save uploaded archive.
            await save_upload(
                file,
                archive_path,
            )

            # Safely extract package.
            extract_archive(
                archive_path,
                extraction_directory,
            )

            # Rename extraction directory using package identity.
            named_directory = temporary_root / package_name

            extraction_directory.rename(named_directory)

            # Run existing PyPI scanner.
            report = scan_directory(named_directory)

            report["package"]["artifact_filename"] = filename

            return report

    except HTTPException:
        raise

    except (
        ValueError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:

        print(
            f"Scan error: {type(error).__name__}: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Package scanning failed. Check backend logs.",
        )

    finally:

        await file.close()


# ============================================================
# STAGE 3
# UPDATE HIJACK DETECTOR
# ============================================================

@app.post("/api/compare-versions")
async def compare_package_versions(
    baseline_file: UploadFile = File(...),
    candidate_file: UploadFile = File(...),
    baseline_version: str = Form(...),
    candidate_version: str = Form(...),
):
    """
    Compare an older and newer version of the same
    Python package.

    Neither package is installed or executed.
    """

    filenames = [
        Path(baseline_file.filename or "").name,
        Path(candidate_file.filename or "").name,
    ]

    try:

        # ----------------------------------------------------
        # STEP 1: Validate filenames and package identity
        # ----------------------------------------------------

        baseline_name = get_package_name(filenames[0])

        candidate_name = get_package_name(filenames[1])

        if (
            normalize_identity(baseline_name)
            != normalize_identity(candidate_name)
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Baseline and candidate must belong "
                    "to the same package."
                ),
            )

        if (
            not baseline_version.strip()
            or not candidate_version.strip()
        ):
            raise HTTPException(
                status_code=400,
                detail="Both package versions are required.",
            )

        # ----------------------------------------------------
        # STEP 2: Create isolated temporary directories
        # ----------------------------------------------------

        with tempfile.TemporaryDirectory(
            prefix="scg_version_diff_"
        ) as temporary_directory:

            root = Path(temporary_directory)

            baseline_archive = root / "baseline_archive"

            candidate_archive = root / "candidate_archive"

            baseline_directory = root / "baseline"

            candidate_directory = root / "candidate"

            # ------------------------------------------------
            # STEP 3: Save both uploaded archives
            # ------------------------------------------------

            await save_upload(
                baseline_file,
                baseline_archive,
            )

            await save_upload(
                candidate_file,
                candidate_archive,
            )

            # ------------------------------------------------
            # STEP 4: Safely extract both archives
            # ------------------------------------------------

            extract_archive(
                baseline_archive,
                baseline_directory,
            )

            extract_archive(
                candidate_archive,
                candidate_directory,
            )

            # ------------------------------------------------
            # STEP 5: Verify package metadata
            # ------------------------------------------------

            baseline_metadata = inspect_package_metadata(
                baseline_directory
            )

            candidate_metadata = inspect_package_metadata(
                candidate_directory
            )

            validate_package_metadata(
                baseline_metadata,
                baseline_name,
            )

            validate_package_metadata(
                candidate_metadata,
                candidate_name,
            )

            if (
                baseline_metadata["found"]
                and candidate_metadata["found"]
                and normalize_identity(
                    baseline_metadata["name"]
                )
                != normalize_identity(
                    candidate_metadata["name"]
                )
            ):
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "The two archives contain "
                        "different package identities."
                    ),
                )

            # ------------------------------------------------
            # STEP 6: Run Stage 3 comparison engine
            # ------------------------------------------------

            report = compare_versions(
                baseline_path=baseline_directory,
                candidate_path=candidate_directory,
                baseline_version=baseline_version.strip(),
                candidate_version=candidate_version.strip(),
            )

            # ------------------------------------------------
            # STEP 7: Add package information
            # ------------------------------------------------

            report["package"] = {
                "name": baseline_name,
                "ecosystem": "pypi",
                "baseline_filename": filenames[0],
                "candidate_filename": filenames[1],
            }

            return report

    except HTTPException:
        raise

    except (
        ValueError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:

        print(
            f"Version comparison error: "
            f"{type(error).__name__}: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Version comparison failed. "
                "Check backend logs."
            ),
        )

    finally:

        await baseline_file.close()

        await candidate_file.close()


# ============================================================
# STAGE 4
# FAKE-BAIT RUNTIME SANDBOX
# ============================================================

@app.post("/api/sandbox")
async def sandbox_package(
    file: UploadFile = File(...),
    entrypoint: str = Form(...),
):
    """
    Safely extract a Python package and execute its selected
    entry point inside the isolated Docker runtime sandbox.
    """

    filename = Path(file.filename or "").name

    if not filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided.",
        )

    if not entrypoint.strip():
        raise HTTPException(
            status_code=400,
            detail="A Python entry point is required.",
        )

    try:

        # ----------------------------------------------------
        # STEP 1: Validate uploaded filename
        # ----------------------------------------------------

        package_name = get_package_name(filename)

        # ----------------------------------------------------
        # STEP 2: Create temporary extraction workspace
        # ----------------------------------------------------

        with tempfile.TemporaryDirectory(
            prefix="scg_sandbox_"
        ) as temporary_directory:

            temporary_root = Path(temporary_directory)

            archive_path = temporary_root / "uploaded_package"

            extraction_directory = temporary_root / "extracted"

            # ------------------------------------------------
            # STEP 3: Save uploaded archive
            # ------------------------------------------------

            await save_upload(
                file,
                archive_path,
            )

            # ------------------------------------------------
            # STEP 4: Safely extract package
            # ------------------------------------------------

            extract_archive(
                archive_path,
                extraction_directory,
            )

            # ------------------------------------------------
            # STEP 5: Validate package identity
            # ------------------------------------------------

            metadata = inspect_package_metadata(
                extraction_directory
            )

            validate_package_metadata(
                metadata,
                package_name,
            )

            # ------------------------------------------------
            # STEP 6: Prepare package directory
            # ------------------------------------------------

            package_directory = (
                temporary_root / package_name
            )

            extraction_directory.rename(
                package_directory
            )

            # ------------------------------------------------
            # STEP 7: Execute package inside Docker
            # ------------------------------------------------

            report = await run_in_threadpool(
                run_sandbox,
                package_directory,
                entrypoint.strip(),
            )

            # ------------------------------------------------
            # STEP 8: Attach package information
            # ------------------------------------------------

            report["package"] = {
                "name": package_name,
                "ecosystem": "pypi",
                "artifact_filename": filename,
            }

            return report

    except HTTPException:
        raise

    except (
        ValueError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except RuntimeError as error:

        print(
            f"Sandbox error: {type(error).__name__}: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

    except Exception as error:

        print(
            f"Sandbox error: {type(error).__name__}: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Runtime sandbox execution failed. "
                "Check backend logs."
            ),
        )

    finally:

        await file.close()

# ============================================================
# UNIFIED ANALYSIS
# STAGES 1 + 2 + 4 + 5
# ============================================================

@app.post("/api/full-analysis")
async def full_package_analysis(
    file: UploadFile = File(...),
    entrypoint: str = Form(...),
):
    """Run static and runtime analysis and combine their findings."""

    filename = Path(file.filename or "").name

    if not filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided.",
        )

    if not entrypoint.strip():
        raise HTTPException(
            status_code=400,
            detail="A Python entry point is required.",
        )

    try:
        package_name = get_package_name(filename)

        with tempfile.TemporaryDirectory(
            prefix="scg_full_analysis_"
        ) as temporary_directory:

            root = Path(temporary_directory)
            archive_path = root / "uploaded_package"
            extraction_directory = root / "extracted"
            package_directory = root / package_name

            # 1. Save and extract package.
            await save_upload(file, archive_path)

            extract_archive(
                archive_path,
                extraction_directory,
            )

            # 2. Validate package identity.
            metadata = inspect_package_metadata(
                extraction_directory
            )

            validate_package_metadata(
                metadata,
                package_name,
            )

            extraction_directory.rename(
                package_directory
            )

            # 3. Static analysis: Stages 1, 2 and existing Stage 5.
            static_report = scan_directory(
                package_directory,
                expected_package_name=package_name,
            )

            static_findings = static_report.get(
                "findings",
                [],
            )

            # 4. Runtime analysis: Stage 4.
            runtime_report = await run_in_threadpool(
                run_sandbox,
                package_directory,
                entrypoint.strip(),
            )

            # 5. Normalize and combine findings.
            unified = prepare_unified_findings(
                static_findings,
                runtime_report,
            )

            # 6. Reassess combined findings using Stage 5.
            final_assessment = assess_findings(
                unified["combined_findings"]
            )

            final_risk = final_assessment["risk"]

            # 7. Return unified report.
            return {
                "schema_version": "1.0.0",
                "analysis_status": "completed",

                "package": {
                    "name": package_name,
                    "ecosystem": "pypi",
                    "artifact_filename": filename,
                    "version": metadata.get("version"),
                },

                "static_analysis": {
                    "scan_id": static_report.get("scan_id"),
                    "scan_status": static_report.get("scan_status"),
                    "coverage": static_report.get("coverage", {}),
                    "original_risk": static_report.get("risk", {}),
                    "findings": static_findings,
                },

                "runtime_analysis": runtime_report,

                "correlation": {
                    "summary": unified["summary"],
                    "correlated_behaviours": unified["correlations"],
                },

                "risk": {
                    "original_static_score": (
                        static_report.get("risk", {}).get("score", 0)
                    ),
                    "context_adjusted_score": final_risk["score"],
                    "severity": final_risk["severity"],
                    "method": final_risk["method"],
                },

                "false_alarm_filter": final_assessment,
                "findings": unified["combined_findings"],
            }

    except HTTPException:
        raise

    except (
        ValueError,
        OSError,
        tarfile.TarError,
        zipfile.BadZipFile,
    ) as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except RuntimeError as error:
        print(f"Full analysis error: {error}")

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

    except Exception as error:
        print(
            f"Full analysis error: "
            f"{type(error).__name__}: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Full package analysis failed. Check backend logs.",
        )

    finally:
        await file.close()
