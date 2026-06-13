from scheduler.enrichment.base_enrichment import BaseEnrichmentJob

from collectors.epss_collector import EPSSCollector


class EPSSEnrichmentJob(BaseEnrichmentJob):

    source = "epss"

    def __init__(self):

        super().__init__()

        self.collector = EPSSCollector()

    def enrich_record(self, record):

        print("EPSS :", record["cve_id"])

        score = self.collector.get_epss_score(

            record["cve_id"]

        )

        self.repository.update_fields(

            record["cve_id"],

            {

                "epss_score": score,

                "epss_processed": True

            }

        )