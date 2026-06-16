from scheduler.enrichment.nvd_enrichment import NVDEnrichmentJob

if __name__ == "__main__":

    job = NVDEnrichmentJob()

    job.run(limit=100)