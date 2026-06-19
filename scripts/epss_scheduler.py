from scheduler.enrichment.epss_enrichment import EPSSEnrichmentJob

if __name__ == "__main__":

    job = EPSSEnrichmentJob()

    job.run(limit=100)
