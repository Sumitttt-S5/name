import importlib.util
import json

spec = importlib.util.spec_from_file_location(
    "process_monitor",
    "/sandbox/process_monitor.py",
)

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

monitor = module.ProcessMonitor()
monitor.start()

import subprocess

result = subprocess.run(
    ["/bin/echo", "SCG harmless process test"],
    capture_output=True,
    text=True,
    check=True,
)

print(json.dumps({
    "test": "process_monitor",
    "command_output": result.stdout.strip(),
    "events": monitor.get_events(),
}, indent=2))
