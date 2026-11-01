import sys


class NetworkMonitor:
    def __init__(self):
        self.events = []

    def audit_hook(self, event, args):
        if event != "socket.connect":
            return

        address = args[1] if len(args) > 1 else None

        self.events.append({
            "event_type": "NETWORK_ATTEMPT",
            "destination": repr(address)[:500],
            "severity": "HIGH",
            "source": "python_audit_hook",
            "network_policy": "disabled",
        })

    def start(self):
        sys.addaudithook(self.audit_hook)

    def get_events(self):
        return list(self.events)
