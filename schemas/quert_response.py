from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class QueryResponse:
    query: str
    resolved_count: int
    returned_count: int
    execution_time_ms: float

    results: List[Dict[str, Any]] = field(default_factory=list)