from pipeline.vulnerability_aggregator import VulnerabilityAggregator
from dataclasses import asdict

aggregator = VulnerabilityAggregator()
record = aggregator.aggregate("CVE-2014-6271")
print(asdict(record))