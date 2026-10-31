
import ast
from typing import Dict, Set, List

from scanner.models import ScanFinding


# Sensitive sources: places where credentials or secrets may originate.
SENSITIVE_SOURCES = {
    "os.getenv",
    "os.environ.get",
}

# Network sinks: functions that may transmit sensitive data.
NETWORK_SINKS = {
    "requests.post",
    "requests.put",
    "requests.patch",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "urllib.request.urlopen",
    "aiohttp.ClientSession.post",
}

# Process execution sinks.
PROCESS_SINKS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "os.system",
}

# Functions that preserve taint while transforming data.
TAINT_PRESERVING_CALLS = {
    "base64.b64encode",
    "base64.b64decode",
    "binascii.hexlify",
    "binascii.unhexlify",
    "codecs.encode",
    "codecs.decode",
    "str",
    "bytes",
}


def get_call_name(node):
    """Convert a function call expression into a dotted name."""

    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr

    if isinstance(node, ast.Call):
        return get_call_name(node.func)

    return ""


class TaintVisitor(ast.NodeVisitor):
    """
    Basic intraprocedural taint analysis.

    Tracks sensitive values from sources such as os.getenv()
    to network and process-execution sinks.

    This is static analysis: package code is never executed.
    """

    def __init__(self, file_path: str):
        self.file_path = str(file_path)

        # Variable name -> set of source line numbers.
        self.environment: Dict[str, Set[int]] = {}

        self.findings: List[ScanFinding] = []
        self.finding_counter = 0

    def expression_origins(self, node) -> Set[int]:
        """
        Return source line numbers that may have influenced an expression.
        """

        if node is None:
            return set()

        # Variable reference.
        if isinstance(node, ast.Name):
            return set(self.environment.get(node.id, set()))

        # Sensitive source, such as os.getenv("API_TOKEN").
        if isinstance(node, ast.Call):
            name = get_call_name(node.func)

            if name in SENSITIVE_SOURCES:
                return {node.lineno}

            # Preserve taint through known conversion/encoding functions.
            if name in TAINT_PRESERVING_CALLS:
                if node.args:
                    return self.expression_origins(node.args[0])
                return set()

            # Preserve taint through string/bytes methods:
            # token.encode(), payload.decode().
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"encode", "decode"}
            ):
                return self.expression_origins(node.func.value)

            return set()

        # String concatenation and other binary operations.
        if isinstance(node, ast.BinOp):
            return (
                self.expression_origins(node.left)
                | self.expression_origins(node.right)
            )

        # Formatted strings.
        if isinstance(node, ast.JoinedStr):
            origins = set()
            for value in node.values:
                origins |= self.expression_origins(value)
            return origins

        if isinstance(node, ast.FormattedValue):
            return self.expression_origins(node.value)

        # Lists, tuples and sets.
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            origins = set()
            for element in node.elts:
                origins |= self.expression_origins(element)
            return origins

        # Dictionaries.
        if isinstance(node, ast.Dict):
            origins = set()
            for key, value in zip(node.keys, node.values):
                origins |= self.expression_origins(key)
                origins |= self.expression_origins(value)
            return origins

        # Subscript access, e.g. payload["token"].
        if isinstance(node, ast.Subscript):
            return (
                self.expression_origins(node.value)
                | self.expression_origins(node.slice)
            )

        # Conditional expression.
        if isinstance(node, ast.IfExp):
            return (
                self.expression_origins(node.test)
                | self.expression_origins(node.body)
                | self.expression_origins(node.orelse)
            )

        # Unary operations.
        if isinstance(node, ast.UnaryOp):
            return self.expression_origins(node.operand)

        # Comparisons.
        if isinstance(node, ast.Compare):
            origins = self.expression_origins(node.left)
            for comparator in node.comparators:
                origins |= self.expression_origins(comparator)
            return origins

        # Named expressions, e.g. (payload := token).
        if isinstance(node, ast.NamedExpr):
            return self.expression_origins(node.value)

        return set()

    def assign_target(self, target, origins: Set[int]):
        """Assign taint information to variables and simple containers."""

        if isinstance(target, ast.Name):
            self.environment[target.id] = set(origins)

        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.assign_target(element, origins)

        elif isinstance(target, ast.Subscript):
            existing = self.expression_origins(target.value)
            self.environment.update({})
            # Container mutation is not fully modelled.
            # Preserve the expression's existing origins where possible.
            if isinstance(target.value, ast.Name):
                self.environment[target.value.id] = existing | set(origins)

    def add_flow_finding(
        self,
        node,
        sink_name: str,
        origins: Set[int],
        argument_name: str,
    ):
        """Create a finding when tainted data reaches a sensitive sink."""

        if not origins:
            return

        self.finding_counter += 1

        source_lines = sorted(origins)

        finding = ScanFinding(
            finding_id=f"PY-TAINT-{self.finding_counter:03d}",
            stage=2,
            rule_id="PY-TAINT-EXFIL-001",
            title="Sensitive data reaches a potentially dangerous sink",
            description=(
                f"Data originating from a sensitive source reaches "
                f"{sink_name}. This may indicate credential exposure, "
                f"data exfiltration, or unsafe process argument handling."
            ),
            severity="HIGH",
            confidence="MEDIUM",
            file=self.file_path,
            line=getattr(node, "lineno", None),
            evidence=[
                *[
                    f"Sensitive source detected at line {line}"
                    for line in source_lines
                ],
                f"Sink: {sink_name}()",
                f"Tainted argument: {argument_name}",
                f"Sink call line: {getattr(node, 'lineno', 'unknown')}",
            ],
            score_contribution=10,
        )

        self.findings.append(finding)

    def visit_Assign(self, node):
        origins = self.expression_origins(node.value)

        for target in node.targets:
            self.assign_target(target, origins)

        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        origins = self.expression_origins(node.value)
        self.assign_target(node.target, origins)
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        origins = (
            self.expression_origins(node.target)
            | self.expression_origins(node.value)
        )
        self.assign_target(node.target, origins)
        self.generic_visit(node)

    def visit_Call(self, node):
        sink_name = get_call_name(node.func)

        if sink_name in NETWORK_SINKS:
            # Inspect payload-related keyword arguments.
            for keyword in node.keywords:
                if keyword.arg in {
                    "data",
                    "json",
                    "params",
                    "headers",
                    "files",
                } or keyword.arg is None:
                    origins = self.expression_origins(keyword.value)

                    self.add_flow_finding(
                        node,
                        sink_name,
                        origins,
                        keyword.arg or "**kwargs",
                    )

            # Inspect positional arguments after the URL argument.
            for index, argument in enumerate(node.args[1:], start=1):
                origins = self.expression_origins(argument)

                self.add_flow_finding(
                    node,
                    sink_name,
                    origins,
                    f"positional argument {index}",
                )

        elif sink_name in PROCESS_SINKS:
            for index, argument in enumerate(node.args):
                origins = self.expression_origins(argument)

                self.add_flow_finding(
                    node,
                    sink_name,
                    origins,
                    f"process argument {index}",
                )

            for keyword in node.keywords:
                origins = self.expression_origins(keyword.value)

                self.add_flow_finding(
                    node,
                    sink_name,
                    origins,
                    keyword.arg or "**kwargs",
                )

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        """
        Analyze each function with an isolated local environment.

        This avoids accidentally carrying local variable taint between
        unrelated functions. Cross-function propagation is not implemented.
        """

        for decorator in node.decorator_list:
            self.visit(decorator)

        for default in node.args.defaults:
            self.visit(default)

        for default in node.args.kw_defaults:
            if default is not None:
                self.visit(default)

        previous_environment = self.environment
        self.environment = {}

        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.environment = previous_environment

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Lambda(self, node):
        previous_environment = self.environment
        self.environment = {}

        try:
            self.visit(node.body)
        finally:
            self.environment = previous_environment


def analyze_taint(tree: ast.AST, file_path: str) -> List[ScanFinding]:
    """
    Public entry point for the taint analysis engine.

    Arguments:
        tree: Parsed Python AST.
        file_path: Path of the source file being analyzed.

    Returns:
        List of ScanFinding objects.
    """

    visitor = TaintVisitor(file_path)
    visitor.visit(tree)

    return visitor.findings
