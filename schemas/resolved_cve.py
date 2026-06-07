from dataclasses import dataclass

@dataclass
class ResolvedCVE:
    cve_id: str
    published: str
    confidence: float
    source: str