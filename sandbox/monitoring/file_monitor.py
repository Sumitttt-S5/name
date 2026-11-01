import os
import sys
from pathlib import Path


class FileMonitor:
    def __init__(self, honeytoken_paths):
        self.honeytokens = {
            str(Path(path).resolve())
            for path in honeytoken_paths
        }
        self.events = []

    def audit_hook(self, event, args):
        if event != "open" or not args:
            return

        raw_path = args[0]

        if not isinstance(raw_path, (str, bytes, os.PathLike)):
            return

        try:
            path = str(Path(raw_path).resolve())
        except (OSError, ValueError):
            return

        if path in self.honeytokens:
            self.events.append({
                "event_type": "HONEYTOKEN_ACCESS",
                "path": path,
                "severity": "HIGH",
                "source": "python_audit_hook",
            })

    def start(self):
        sys.addaudithook(self.audit_hook)

    def get_events(self):
        return list(self.events)


if __name__ == "__main__":
    decoy = Path("/decoys/.env.fake")

    monitor = FileMonitor([decoy])
    monitor.start()

    try:
        with decoy.open("r", encoding="utf-8") as file:
            file.read()
    except FileNotFoundError:
        print("Test decoy not mounted; monitoring hook is active.")

    print(monitor.get_events())
