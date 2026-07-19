from dataclasses import dataclass, field
from typing import List


@dataclass
class InventoryComponent:
    host: str
    vendor: str
    product: str
    version: str
    environment: str = ""
    business_criticality: str = "Medium"


@dataclass
class MatchedVulnerability:
    cve_id: str
    severity: str
    cvss_score: float
    epss_score: float
    threat_score: float
    kev: bool
    exploit_available: bool


@dataclass
class ComponentReport:
    host: str
    vendor: str
    product: str
    version: str
    vulnerabilities: List[MatchedVulnerability] = field(default_factory=list)
    highest_threat_score: float = 0.0
    risk_level: str = "UNKNOWN"


@dataclass
class InventorySummary:
    total_components: int
    affected_components: int
    critical: int
    high: int
    medium: int
    low: int
    kev: int
    exploitable: int
    overall_risk: str = "UNKNOWN"
    overall_threat_score: float = 0.0


@dataclass
class InventoryReport:
    summary: InventorySummary
    components: List[ComponentReport] = field(default_factory=list)
