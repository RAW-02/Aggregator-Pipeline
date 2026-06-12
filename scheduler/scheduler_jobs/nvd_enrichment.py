import time
from storage.json_repo import JsonRepository
from pipeline.enrichment.nvd_enrichment_pipeline import NVDEnrichmentPipeline

class NVDEnrichmentJob:
    def __init__(self):
        self.repository = JsonRepository()
        self.pipeline = NVDEnrichmentPipeline()

    def run(self):
        records = self.repository.get_unprocessed_nvd()
        print()
        print("Total Pending :", len(records))
        print()

        count = 0
        for record in records:
            self.pipeline.enrich(record)
            count += 1
            time.sleep(1)

            if count >= 100:
                break

        print()
        print("Updated :", count)