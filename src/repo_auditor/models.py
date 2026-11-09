from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def color(self) -> str:
        match self:
            case Severity.CRITICAL:
                return "bold red"
            case Severity.HIGH:
                return "red"
            case Severity.MEDIUM:
                return "yellow"
            case Severity.LOW:
                return "blue"
            case Severity.INFO:
                return "green"


@dataclass
class Finding:
    category: str
    severity: Severity
    title: str
    description: str
    file_path: Path | None = None
    line_number: int | None = None
    snippet: str | None = None


@dataclass
class AuditReport:
    target_path: Path
    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def has_threats(self) -> bool:
        return (self.critical_count + self.high_count) > 0
