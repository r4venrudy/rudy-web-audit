from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Check:
    id: str
    title: str
    status: str
    severity: str
    evidence: str
    recommendation: str = ""
    hop: int | None = None


@dataclass
class Hop:
    url: str
    status: int
    ip: str
    elapsed_ms: float
    headers: list[tuple[str, str]]
    tls: dict[str, Any] | None = None


@dataclass
class Audit:
    target: str
    target_id: str
    hops: list[Hop] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    error: str | None = None
    score: int | None = None
    grade: str = "Unrated"

    def to_dict(self) -> dict:
        return asdict(self)
