
import importlib.util
import json

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


collector_module = load_module(
    "event_collector",
    "/sandbox/event_collector.py",
)

file_module = load_module(
    "file_monitor",
    "/sandbox/file_monitor.py",
)

process_module = load_module(
    "process_monitor",
    "/sandbox/process_monitor.py",
)

network_module = load_module(
    "network_monitor",
    "/sandbox/network_monitor.py",
)

collector = collector_module.EventCollector()

# Start all three Python audit monitors.
file_monitor = file_module.FileMonitor(["/decoys/.env.fake"])
process_monitor = process_module.ProcessMonitor()
network_monitor = network_module.NetworkMonitor()

file_monitor.start()
process_monitor.start()
network_monitor.start()

# Generate controlled test events.
with open("/decoys/.env.fake", "r") as honeytoken:
    honeytoken.read()

import subprocess
subprocess.run(
    ["/bin/echo", "SCG runtime integration test"],
    capture_output=True,
    text=True,
    check=True,
)

import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)

try:
    sock.connect(("192.0.2.1", 443))
except OSError:
    pass
finally:
    sock.close()

# Combine the actual events detected by the monitors.
collector.ingest_monitor_events(file_monitor.get_events())
collector.ingest_monitor_events(process_monitor.get_events())
collector.ingest_monitor_events(network_monitor.get_events())

report = collector.generate_report()

print(json.dumps({
    "test": "runtime_report_integration",
    "report": report,
}, indent=2))

# Verify that all three event categories were captured.
detected_types = {
    event["event_type"]
    for event in report["events"]
}

required_types = {
    "HONEYTOKEN_ACCESS",
    "PROCESS_EXECUTION",
    "NETWORK_ATTEMPT",
}

assert required_types.issubset(detected_types), (
    f"Missing events: {required_types - detected_types}"
)

print("\nPASS: All three monitor events reached the unified report.")
