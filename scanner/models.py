from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Literal

Severity = Literal["Low", "Medium", "High", "Critical", "Info"]

SEVERITY_SCORE: Dict[str, int] = {
    "Info": 0,
    "Low": 1,
    "Medium": 3,
    "High": 7,
    "Critical": 10,
}


@dataclass
class PortService:
    port: int
    proto: str = "tcp"
    service: str = "unknown"
    banner: Optional[str] = None
    version: Optional[str] = None


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    type: Literal["misconfiguration", "cve", "info"]
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    affected: Optional[Dict[str, Any]] = None


@dataclass
class HostResult:
    host: str
    reachable: bool = True
    open_ports: List[PortService] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
