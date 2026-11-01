import sys
import os


class ProcessMonitor:
    def __init__(self):
        self.events = []

    def audit_hook(self, event, args):
        if event not in {
            "subprocess.Popen",
            "os.system",
            "os.exec",
            "os.spawn",
        }:
            return

        self.events.append({
            "event_type": "PROCESS_EXECUTION",
            "audit_event": event,
            "details": repr(args)[:1000],
            "severity": "MEDIUM",
            "source": "python_audit_hook",
        })

    def start(self):
        sys.addaudithook(self.audit_hook)

    def get_events(self):
        return list(self.events)


if __name__ == "__main__":
    import json
    import subprocess

    monitor = ProcessMonitor()
    monitor.start()

    subprocess.run(
        ["/bin/echo", "SCG harmless process test"],
        check=True,
        capture_output=True,
        text=True,
    )

    print(json.dumps({
        "test": "process_monitor",
        "events": monitor.get_events(),
    }, indent=2))
