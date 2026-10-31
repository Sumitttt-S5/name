import ast
import hashlib

from .models import ScanFinding, ParsedFile


def get_call_name(node):
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr

    return ""


class SecurityVisitor(ast.NodeVisitor):

    def __init__(self, file_path):
        self.file_path = file_path
        self.findings = []

    def add_finding(
        self, node, rule_id, title, description,
        severity, confidence, evidence, score
    ):
        raw = f"{self.file_path}:{node.lineno}:{rule_id}"
        finding_id = hashlib.sha256(raw.encode()).hexdigest()[:12]

        self.findings.append(
            ScanFinding(
                finding_id=finding_id,
                stage=2,
                rule_id=rule_id,
                title=title,
                description=description,
                severity=severity,
                confidence=confidence,
                file=self.file_path,
                line=getattr(node, "lineno", None),
                evidence=[evidence],
                score_contribution=score
            )
        )

    def visit_Call(self, node):
        name = get_call_name(node.func)

        if name in {"eval", "exec"}:
            self.add_finding(
                node, "PY-DYNAMIC-001",
                "Dynamic code execution",
                "Code is dynamically executed. Review its origin and content.",
                "HIGH", "MEDIUM", f"{name}() detected", 4
            )

        elif name == "os.system":
            self.add_finding(
                node, "PY-PROCESS-001",
                "Operating system command execution",
                "The package executes an operating-system command.",
                "HIGH", "MEDIUM", "os.system() detected", 5
            )

        elif name.startswith("subprocess."):
            shell_true = any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            )

            self.add_finding(
                node, "PY-PROCESS-002",
                "Subprocess execution",
                "The package starts an external process.",
                "HIGH" if shell_true else "MEDIUM",
                "MEDIUM",
                f"{name} detected; shell=True: {shell_true}",
                5 if shell_true else 2
            )

        elif name.startswith((
            "requests.", "httpx.", "urllib.request.",
            "socket.", "aiohttp."
        )):
            self.add_finding(
                node, "PY-NETWORK-001",
                "Network communication",
                "The package performs a network operation.",
                "MEDIUM", "LOW", f"{name} detected", 1
            )

        elif name in {"os.getenv", "os.environ.get"}:
            self.add_finding(
                node, "PY-SECRET-SOURCE-001",
                "Environment variable access",
                "The package reads an environment variable.",
                "LOW", "LOW", f"{name} detected", 1
            )

        elif name in {
            "base64.b64decode",
            "binascii.unhexlify",
            "codecs.decode"
        }:
            self.add_finding(
                node, "PY-OBFUSCATION-001",
                "Encoded data decoding",
                "The package decodes encoded content.",
                "LOW", "LOW", f"{name} detected", 1
            )

        self.generic_visit(node)


def analyze_python_file(parsed_file: ParsedFile):
    visitor = SecurityVisitor(parsed_file.path)
    visitor.visit(parsed_file.tree)
    return visitor.findings