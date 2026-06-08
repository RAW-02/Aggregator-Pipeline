import json
from pipeline.QueryPipeline import QueryPipeline

pipeline = QueryPipeline()
response = pipeline.process(query="CVE-2014-6721", limit=3)

print(json.dumps(response, indent=4))