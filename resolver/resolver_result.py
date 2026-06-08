from dataclasses import dataclass

@dataclass
class ResolverResult:
    cve_id: str
    score: float
    source: str
    matched_by: str
    published: str
    last_modified: str