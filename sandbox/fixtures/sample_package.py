
import os
import subprocess
import socket

print("SCG SAMPLE PACKAGE STARTED")

# Test 1: Read the synthetic honeytoken.
try:
    with open("/decoys/.env.fake", "r") as file:
        file.read()
    print("Honeytoken test completed")
except OSError:
    print("Honeytoken unavailable")

# Test 2: Create a harmless process.
subprocess.run(
    ["/bin/echo", "SCG package process test"],
    capture_output=True,
    text=True,
    check=True,
)

print("Process test completed")

# Test 3: Attempt a network connection.
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(1)

try:
    sock.connect(("192.0.2.1", 443))
except OSError:
    print("Network connection blocked as expected")
finally:
    sock.close()

print("SCG SAMPLE PACKAGE FINISHED")
