
import contextlib
import importlib.util
import io
import json
import os
import runpy
import sys
import platform
from datetime import datetime, timezone
from pathlib import Path


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)

    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load monitoring module: {name}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LimitedOutput(io.StringIO):
    """Capture package output with a maximum size."""

    def __init__(self, limit=10000):
        super().__init__()
        self.limit = limit

    def write(self, text):
        remaining = self.limit - len(self.getvalue())

        if remaining > 0:
            super().write(text[:remaining])

        return len(text)


def main():
    started_at = datetime.now(timezone.utc)

    if len(sys.argv) < 2:
        print(json.dumps({
            "status": "failed",
            "error": "Missing package entry-point argument.",
        }, indent=2))
        sys.exit(2)

    target = Path(sys.argv[1]).resolve()
    input_root = Path("/input").resolve()

    try:
        target.relative_to(input_root)
    except ValueError:
        print(json.dumps({
            "status": "failed",
            "error": "Package entry point must be inside /input.",
        }, indent=2))
        sys.exit(2)

    if not target.is_file() or target.suffix != ".py":
        print(json.dumps({
            "status": "failed",
            "error": "Entry point must be an existing Python file.",
        }, indent=2))
        sys.exit(2)

    # Load monitoring modules before activating audit hooks.
    base = Path("/sandbox")

    collector_module = load_module(
        "event_collector",
        base / "event_collector.py",
    )

    file_module = load_module(
        "file_monitor",
        base / "file_monitor.py",
    )

    process_module = load_module(
        "process_monitor",
        base / "process_monitor.py",
    )

    network_module = load_module(
        "network_monitor",
        base / "network_monitor.py",
    )

    collector = collector_module.EventCollector()

    file_monitor = file_module.FileMonitor([
        "/decoys/.env.fake",
        "/decoys/credentials.txt",
    ])

    process_monitor = process_module.ProcessMonitor()
    network_monitor = network_module.NetworkMonitor()

    # Activate monitoring before executing untrusted package code.
    file_monitor.start()
    process_monitor.start()
    network_monitor.start()

    captured_output = LimitedOutput()
    execution_status = "completed"
    execution_error = None
    exit_code = 0

    try:
        with contextlib.redirect_stdout(captured_output):
            runpy.run_path(
                str(target),
                run_name="__main__",
            )

    except SystemExit as error:
        exit_code = error.code if isinstance(error.code, int) else 1

        if exit_code != 0:
            execution_status = "failed"
            execution_error = f"Package exited with code {exit_code}"

    except BaseException as error:
        execution_status = "failed"
        exit_code = 1
        execution_error = (
            f"{type(error).__name__}: {str(error)[:1000]}"
        )

    # Import actual events from all monitoring modules.
    collector.ingest_monitor_events(file_monitor.get_events())
    collector.ingest_monitor_events(process_monitor.get_events())
    collector.ingest_monitor_events(network_monitor.get_events())

    report = collector.generate_report()

    report.update({
        "worker": "Supply Chain Guardian Runtime Sandbox",
        "execution_status": execution_status,
        "exit_code": exit_code,
        "package_entry_point": str(target),
        "python_version": platform.python_version(),
        "user_id": os.getuid() if hasattr(os, "getuid") else None,
        "network_policy": "disabled_by_container_configuration",
        "execution_started_at": started_at.isoformat(),
        "execution_output": captured_output.getvalue(),
        "execution_error": execution_error,
    })

    print(json.dumps(report, indent=2))

    if execution_status != "completed":
        sys.exit(1)


if __name__ == "__main__":
    main()
