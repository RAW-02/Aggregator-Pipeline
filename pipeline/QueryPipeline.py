import time
from dataclasses import asdict

from resolver.input_resolver import InputResolver
from pipeline.vulnerability_aggregator import VulnerabilityAggregator
from schemas.quert_response import QueryResponse  
from pipeline.ranking_engine import RankingEngine

from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed

class QueryPipeline:
    def __init__(self):
        self.resolver = InputResolver()
        self.aggregator = VulnerabilityAggregator()

    def process(self, query: str, limit: int = 10, sort_by: str = "threat_score"):
        start_time = time.time()

        # Resolve User Query
        resolved_cves = self.resolver.resolve(query)
        total_resolved = len(resolved_cves)

        resolved = resolved_cves[:limit]

        # Aggregate
        records = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(self.aggregator.aggregate, item.cve_id): item.cve_id for item in resolved}

            for future in as_completed(futures):
                try:
                    records.append(future.result())
                except Exception as e:
                    print(f"Aggregation failed : {e}")
            
        # Sort
        records = RankingEngine.rank(records, sort_by)

        execution_time = round((time.time() - start_time) * 1000, 2)

        response = QueryResponse(
            query=query,
            resolved_count=total_resolved,
            returned_count=len(records),
            execution_time_ms=execution_time,
            results=[asdict(record) for record in records]
        )

        return asdict(response)