
import importlib.util
import json
from pathlib import Path

monitor_path = Path("/sandbox/file_monitor.py")

spec = importlib.util.spec_from_file_location(
    "file_monitor",
    monitor_path,
)

if spec is None or spec.loader is None:
    raise RuntimeError("Could not load file monitor")

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

FileMonitor = module.FileMonitor

decoy = Path("/decoys/.env.fake")

monitor = FileMonitor([decoy])
monitor.start()

with decoy.open("r", encoding="utf-8") as file:
    content = file.read()

print(json.dumps({
    "test": "honeytoken_access",
    "file_read": bool(content),
    "events": monitor.get_events()
}, indent=2))
