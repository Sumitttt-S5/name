
import json
import time
from datetime import datetime, timezone


class EventCollector:
    def __init__(self):
        self.events = []
        self.started_at = time.time()

    def record(
        self,
        event_type,
        details,
        severity="INFO",
        source="scg_monitor",
    ):
        event = {
            "event_id": len(self.events) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "details": details,
        }

        self.events.append(event)

    def ingest_monitor_events(self, monitor_events):
        """Import actual events detected by the monitoring modules."""
        for event in monitor_events:
            event_type = event.get("event_type", "UNKNOWN")

            details = {
                key: value
                for key, value in event.items()
                if key not in {"event_type", "severity", "source"}
            }

            self.record(
                event_type=event_type,
                details=details,
                severity=event.get("severity", "INFO"),
                source=event.get("source", "unknown_monitor"),
            )

    def record_honeytoken_access(self, path):
        self.record(
            "HONEYTOKEN_ACCESS",
            {
                "path": path,
                "description": "Synthetic decoy file accessed",
            },
            "HIGH",
        )

    def record_process(self, executable, arguments):
        self.record(
            "PROCESS_EXECUTION",
            {
                "executable": executable,
                "arguments": arguments,
            },
            "MEDIUM",
        )

    def record_network_attempt(self, destination):
        self.record(
            "NETWORK_ATTEMPT",
            {
                "destination": destination,
                "network_policy": "disabled",
            },
            "HIGH",
        )

    def generate_report(self):
        severity_counts = {}

        for event in self.events:
            severity = event["severity"]
            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )

        return {
            "engine": "SCG Runtime Event Collector",
            "status": "completed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(
                time.time() - self.started_at, 3
            ),
            "total_events": len(self.events),
            "severity_counts": severity_counts,
            "events": self.events,
        }


if __name__ == "__main__":
    collector = EventCollector()

    # Simulated demonstration events, not observed runtime evidence.
    collector.record_honeytoken_access("/decoys/.env.fake")
    collector.record_process("/usr/bin/python", ["suspicious_script.py"])
    collector.record_network_attempt("example.invalid:443")

    print(json.dumps(collector.generate_report(), indent=2))
