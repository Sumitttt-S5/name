
import ast
from collections import defaultdict
from typing import DefaultDict, Set, List

from scanner.models import ScanFinding


# ---------------------------------------------------------
# 1. TAINT SOURCES
# ---------------------------------------------------------

# Sources of credentials and sensitive information.
SENSITIVE_SOURCES = {
    "os.getenv",
    "os.environ.get",
}

# Sources of untrusted user-controlled input.
UNTRUSTED_SOURCES = {
    "input",
}

# Network sinks.
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

# Calls that preserve taint.
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


# ---------------------------------------------------------
# 2. AST HELPERS
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# 3. TAINT VISITOR
# ---------------------------------------------------------

class TaintVisitor(ast.NodeVisitor):
    """
    Intraprocedural taint analysis.

    Tracks:
        - Sensitive data from environment variables.
        - Untrusted data from input().
        - Propagation through assignments and expressions.
        - Sensitive and untrusted data reaching dangerous sinks.

    Package code is never executed.
    """

    def __init__(self, file_path: str):
        self.file_path = str(file_path)

        # Variable name -> source line numbers.
        self.environment: dict[str, Set[int]] = {}

        # Source line -> source categories.
        self.source_kinds: DefaultDict[int, Set[str]] = defaultdict(set)

        self.findings: List[ScanFinding] = []
        self.finding_counter = 0

    # -----------------------------------------------------
    # SOURCE TRACKING
    # -----------------------------------------------------

    def expression_origins(self, node) -> Set[int]:
        """Return source lines that may have influenced an expression."""

        if node is None:
            return set()

        if isinstance(node, ast.Name):
            return set(self.environment.get(node.id, set()))

        if isinstance(node, ast.Call):
            name = get_call_name(node.func)

            if name in SENSITIVE_SOURCES:
                self.source_kinds[node.lineno].add("SENSITIVE_DATA")
                return {node.lineno}

            if name in UNTRUSTED_SOURCES:
                self.source_kinds[node.lineno].add("UNTRUSTED_INPUT")
                return {node.lineno}

            if name in TAINT_PRESERVING_CALLS:
                origins = set()

                for argument in node.args:
                    origins |= self.expression_origins(argument)

                for keyword in node.keywords:
                    origins |= self.expression_origins(keyword.value)

                return origins

            # Preserve taint through encode/decode methods.
            if (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"encode", "decode"}
            ):
                return self.expression_origins(node.func.value)

            return set()

        if isinstance(node, ast.BinOp):
            return (
                self.expression_origins(node.left)
                | self.expression_origins(node.right)
            )

        if isinstance(node, ast.JoinedStr):
            origins = set()

            for value in node.values:
                origins |= self.expression_origins(value)

            return origins

        if isinstance(node, ast.FormattedValue):
            return self.expression_origins(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            origins = set()

            for element in node.elts:
                origins |= self.expression_origins(element)

            return origins

        if isinstance(node, ast.Dict):
            origins = set()

            for key, value in zip(node.keys, node.values):
                origins |= self.expression_origins(key)
                origins |= self.expression_origins(value)

            return origins

        if isinstance(node, ast.Subscript):
            return (
                self.expression_origins(node.value)
                | self.expression_origins(node.slice)
            )

        if isinstance(node, ast.IfExp):
            return (
                self.expression_origins(node.test)
                | self.expression_origins(node.body)
                | self.expression_origins(node.orelse)
            )

        if isinstance(node, ast.UnaryOp):
            return self.expression_origins(node.operand)

        if isinstance(node, ast.Compare):
            origins = self.expression_origins(node.left)

            for comparator in node.comparators:
                origins |= self.expression_origins(comparator)

            return origins

        if isinstance(node, ast.NamedExpr):
            return self.expression_origins(node.value)

        return set()

    def get_source_kinds(self, origins: Set[int]) -> Set[str]:
        """Determine which source categories contributed to an expression."""

        kinds = set()

        for line in origins:
            kinds.update(self.source_kinds.get(line, set()))

        return kinds

    # -----------------------------------------------------
    # VARIABLE ASSIGNMENT
    # -----------------------------------------------------

    def assign_target(self, target, origins: Set[int]):
        """Assign taint information to variables and simple containers."""

        if isinstance(target, ast.Name):
            self.environment[target.id] = set(origins)

        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.assign_target(element, origins)

        elif isinstance(target, ast.Subscript):
            if isinstance(target.value, ast.Name):
                name = target.value.id

                existing = self.environment.get(name, set())

                self.environment[name] = (
                    set(existing) | set(origins)
                )

    # -----------------------------------------------------
    # FINDING GENERATION
    # -----------------------------------------------------

    def add_flow_finding(
        self,
        node,
        sink_name: str,
        origins: Set[int],
        argument_name: str,
    ):
        """Create a finding when tainted data reaches a dangerous sink."""

        if not origins:
            return

        source_kinds = self.get_source_kinds(origins)

        if not source_kinds:
            return

        self.finding_counter += 1

        source_lines = sorted(origins)

        is_untrusted_process_flow = (
            "UNTRUSTED_INPUT" in source_kinds
            and sink_name in PROCESS_SINKS
        )

        if is_untrusted_process_flow:
            rule_id = "PY-TAINT-CMD-001"
            title = "Untrusted input reaches process execution"

            description = (
                "Data originating from user-controlled input "
                "reaches a process-execution function. This may "
                "create command-injection risk."
            )

            severity = "HIGH"
            confidence = "HIGH"
            score = 20

        elif "SENSITIVE_DATA" in source_kinds:
            rule_id = "PY-TAINT-EXFIL-001"
            title = "Sensitive data reaches a potentially dangerous sink"

            description = (
                f"Data originating from a sensitive source reaches "
                f"{sink_name}. This may indicate credential exposure, "
                f"data exfiltration, or unsafe process argument handling."
            )

            severity = "HIGH"
            confidence = "MEDIUM"
            score = 10

        else:
            rule_id = "PY-TAINT-UNTRUSTED-FLOW-001"
            title = "Untrusted input reaches a sensitive operation"

            description = (
                f"User-controlled input reaches {sink_name}. "
                "Review how the data is validated and used."
            )

            severity = "MEDIUM"
            confidence = "MEDIUM"
            score = 8

        source_evidence = [
            f"Source detected at line {line}"
            for line in source_lines
        ]

        source_evidence.append(
            f"Source categories: {', '.join(sorted(source_kinds))}"
        )

        source_evidence.extend([
            f"Sink: {sink_name}()",
            f"Tainted argument: {argument_name}",
            f"Sink call line: {getattr(node, 'lineno', 'unknown')}",
        ])

        finding = ScanFinding(
            finding_id=f"PY-TAINT-{self.finding_counter:03d}",
            stage=2,
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            file=self.file_path,
            line=getattr(node, "lineno", None),
            evidence=source_evidence,
            score_contribution=score,
        )

        self.findings.append(finding)

    # -----------------------------------------------------
    # ASSIGNMENT VISITORS
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # SINK ANALYSIS
    # -----------------------------------------------------

    def visit_Call(self, node):
        sink_name = get_call_name(node.func)

        if sink_name in NETWORK_SINKS:

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

            # Inspect positional arguments after the URL.
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

    # -----------------------------------------------------
    # FUNCTION SCOPE
    # -----------------------------------------------------

    def visit_FunctionDef(self, node):
        """
        Analyze functions with isolated local environments.

        Cross-function propagation is not implemented.
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


# ---------------------------------------------------------
# 4. PUBLIC ENTRY POINT
# ---------------------------------------------------------

def analyze_taint(tree: ast.AST, file_path: str) -> List[ScanFinding]:
    """
    Analyze a Python AST for sensitive and untrusted data flows.

    Returns:
        List of ScanFinding objects.
    """

    visitor = TaintVisitor(file_path)
    visitor.visit(tree)

    return visitor.findings
