from dataclasses import dataclass, field


@dataclass
class ParseIssue:
    file: str
    error: str
    line: int | None = None


@dataclass
class ParsedFile:
    path: str
    source: str
    tree: object


@dataclass
class ScanFinding:
    finding_id: str
    stage: int
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    file: str | None
    line: int | None
    evidence: list[str] = field(default_factory=list)
    score_contribution: int = 0

    def to_dict(self):
        return {
            "finding_id": self.finding_id,
            "stage": self.stage,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "confidence": self.confidence,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "mitre_techniques": [],
            "score_contribution": self.score_contribution
        }