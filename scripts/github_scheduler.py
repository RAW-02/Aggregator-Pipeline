from scheduler.enrichment.github_enrichment import GithubEnrichmentJob

if __name__ == "__main__":

    job = GithubEnrichmentJob()

    job.run(limit=50)
