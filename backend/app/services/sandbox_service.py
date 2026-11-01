
import json
import subprocess
import uuid

from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DOCKER_IMAGE = "scg-sandbox-worker:1.0"

REPORT_DIRECTORY = PROJECT_ROOT / "sandbox" / "reports"

HONEYTOKEN_DIRECTORY = (
    PROJECT_ROOT / "sandbox" / "fixtures" / "honeytokens"
)

EXECUTION_TIMEOUT = 30
MAX_REPORT_OUTPUT = 20_000


def docker_command(args, timeout=10):
    """Run a Docker CLI command and return its output."""

    return subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def save_report(report):
    """Persist a runtime report as JSON."""

    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    report_id = uuid.uuid4().hex

    report_path = REPORT_DIRECTORY / (
        f"runtime-{report_id}.json"
    )

    report["report_id"] = report_id
    report["report_file"] = str(
        report_path.relative_to(PROJECT_ROOT))

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )


    return report


def run_sandbox(package_directory, entrypoint):
    """Execute an extracted Python package in an isolated container."""

    package_directory = Path(package_directory).resolve()

    if not package_directory.is_dir():
        raise ValueError("Package directory does not exist.")

    relative_entrypoint = Path(entrypoint)

    if (
        relative_entrypoint.is_absolute()
        or ".." in relative_entrypoint.parts
        or relative_entrypoint.suffix != ".py"
    ):
        raise ValueError("Invalid Python entry point.")

    target = (
        package_directory / relative_entrypoint
    ).resolve()

    if not target.is_relative_to(package_directory):
        raise ValueError("Entry point escapes package directory.")

    if not target.is_file():
        raise ValueError("Python entry point was not found.")

    if not HONEYTOKEN_DIRECTORY.is_dir():
        raise RuntimeError("Honeytoken directory is missing.")

    container_name = f"scg-runtime-{uuid.uuid4().hex[:12]}"

    mount_package = (
        f"type=bind,source={package_directory},"
        "target=/input,readonly"
    )

    mount_honeytokens = (
        f"type=bind,source={HONEYTOKEN_DIRECTORY},"
        "target=/decoys,readonly"
    )

    relative_container_path = relative_entrypoint.as_posix()

    container_entrypoint = (
        f"/input/{relative_container_path}"
    )

    created = False
    timed_out = False
    report_output = ""

    started_at = datetime.now(timezone.utc)

    try:
        # Create a fresh, isolated container.
        create_result = docker_command([
            "create",
            "--name", container_name,
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--pids-limit", "64",
            "--memory", "128m",
            "--cpus", "0.5",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--mount", mount_package,
            "--mount", mount_honeytokens,
            "--log-driver", "local",
            "--log-opt", "max-size=1m",
            "--log-opt", "max-file=2",
            DOCKER_IMAGE,
            container_entrypoint,
        ])

        if create_result.returncode != 0:
            raise RuntimeError(
                f"Docker container creation failed: "
                f"{create_result.stderr[:1000]}"
            )

        created = True

        # Start the container.
        start_result = docker_command([
            "start",
            container_name,
        ])

        if start_result.returncode != 0:
            raise RuntimeError(
                f"Docker container start failed: "
                f"{start_result.stderr[:1000]}"
            )

        # Wait for execution, enforcing the timeout.
        try:
            wait_result = docker_command(
                ["wait", container_name],
                timeout=EXECUTION_TIMEOUT,
            )

            if wait_result.returncode != 0:
                raise RuntimeError(
                    "Could not retrieve container exit status."
                )

            exit_code = int(wait_result.stdout.strip())

        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124

            docker_command(
                ["kill", container_name],
                timeout=10,
            )

        # Retrieve bounded container logs.
        logs_result = docker_command([
            "logs",
            "--tail", "200",
            container_name,
        ])

        report_output = (
            logs_result.stdout + logs_result.stderr
        )[:MAX_REPORT_OUTPUT]

        if timed_out:
            report = {
                "engine": "SCG Runtime Sandbox",
                "status": "timeout",
                "execution_status": "timed_out",
                "exit_code": exit_code,
                "execution_error": (
                    f"Execution exceeded {EXECUTION_TIMEOUT} seconds."
                ),
                "container_output": report_output,
            }

        else:
            try:
                report = json.loads(report_output)

            except json.JSONDecodeError:
                report = {
                    "engine": "SCG Runtime Sandbox",
                    "status": "invalid_worker_report",
                    "execution_status": "failed",
                    "exit_code": exit_code,
                    "container_output": report_output,
                    "execution_error": (
                        "Worker did not produce valid JSON."
                    ),
                }

        report["container_exit_code"] = exit_code
        report["backend_execution_started_at"] = (
            started_at.isoformat()
        )

        return save_report(report)

    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "Docker orchestration command timed out."
        ) from error

    finally:
        # Always remove the container, including on timeout.
        if created:
            docker_command(
                ["rm", "-f", container_name],
                timeout=10,
            )
