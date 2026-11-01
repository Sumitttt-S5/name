import importlib.util
import json
import socket

spec = importlib.util.spec_from_file_location(
    "network_monitor",
    "/sandbox/network_monitor.py",
)

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

monitor = module.NetworkMonitor()
monitor.start()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)

connection_result = "not attempted"

try:
    sock.connect(("192.0.2.1", 443))
    connection_result = "unexpectedly connected"
except OSError as error:
    connection_result = type(error).__name__
finally:
    sock.close()

print(json.dumps({
    "test": "network_monitor",
    "connection_result": connection_result,
    "events": monitor.get_events(),
}, indent=2))
