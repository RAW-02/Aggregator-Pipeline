# from pipeline.vulnerability_aggregator import VulnerabilityAggregator
from storage.json_repo import JsonRepository
from pipeline.aggregation_pipeline import AggregationPipeline


class PipelineRunner:
    def __init__(self):
        self.pipeline = AggregationPipeline()

    def process(self, cve):
        try:
            record = self.pipeline.run(cve)
            print(f"✓ Stored {record.cve_id}")

        except Exception as e:
            print(f"✗ Failed {cve}: {e}")

    def process_batch(self, cves):
        for cve in cves:
            self.process(cve)



# Before Aggregation Pipeline
# class PipelineRunner:
#     def __init__(self):
#         self.aggregator = VulnerabilityAggregator()
#         self.repository = JsonRepository()

#     def process(self, cve):
#         try:
#             record = self.aggregator.aggregate(cve)
#             self.repository.upsert(record)
#             print(f"Stored {record.cve_id}")
#         except Exception as e:
#             print(f"✗ Failed {record.cve_id}", e)

#     def process_batch(self, cves):
#         for cve in cves:
#             self.process(cve)