from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    def __lt__(self, other):
        return self.numeric < other.numeric


@dataclass
class Finding:
    title: str
    severity: Severity
    vuln_type: str
    url: str
    description: str
    evidence: str = ""
    request: str = ""
    response: str = ""
    parameter: str = ""
    payload: str = ""
    remediation: str = ""
    confidence: str = "medium"  # low, medium, high
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def fingerprint(self) -> str:
        import hashlib
        key = f"{self.vuln_type}|{self.url}|{self.parameter}|{self.payload}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "severity": self.severity.value,
            "vuln_type": self.vuln_type,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "request": self.request,
            "response": self.response,
            "parameter": self.parameter,
            "payload": self.payload,
            "remediation": self.remediation,
            "confidence": self.confidence,
            "references": self.references,
            "tags": self.tags,
            "timestamp": self.timestamp,
            "fingerprint": self.fingerprint,
        }
