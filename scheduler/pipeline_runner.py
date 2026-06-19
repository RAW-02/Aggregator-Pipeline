from pipeline.aggregation_pipeline import AggregationPipeline
from pipeline.refresh_pipeline import RefreshPipeline
from concurrent.futures import ThreadPoolExecutor


class PipelineRunner:
    def __init__(self):
        self.pipeline = AggregationPipeline()
        self.refresh_pipeline = RefreshPipeline()

    def process(self, cve):
        try:
            record = self.pipeline.run(cve)
            print(f"✓ Stored {record.cve_id}")
            return record

        except Exception as e:
            print(f"✗ Failed {cve}: {e}")

    def process_batch(self, cves):
        for cve in cves:
            self.process(cve)

    def refresh(self, cve):
        return self.refresh_pipeline.run(cve)

    def refresh_batch(self, cves):
        print("Batch Refreshing working ....")
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(self.refresh, cves))
            successful = []
            failed = []

            for result in results:
                if result is None:
                    failed.append(result)

                else:
                    successful.append(result)

            print(f"Success : {len(successful)}")
            print(f"Failed  : {len(failed)}")
            return successful
