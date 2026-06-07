import json
from pipeline.QueryPipeline import QueryPipeline

pipeline = QueryPipeline()
response = pipeline.process(query="Microsoft", limit=3)

print(json.dumps(response, indent=4))