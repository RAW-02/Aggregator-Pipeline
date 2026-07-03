from scheduler.enrichment.base_enrichment import BaseEnrichmentJob
from github_engine.main import github_engine


class GithubEnrichmentJob(BaseEnrichmentJob):

    source = "github"

    def get_records(self, limit):
        return self.repository.get_pending_github(limit)

    def enrich_record(self, record):

        cve_id = record["cve_id"]

        print("GITHUB :", cve_id)

        github = github_engine(cve_id)

        if github is None:
            return None

        return {
            "cve_id": cve_id,
            "fields": {
                "github_repository_count": github.get("repository_count", 0),
                "github_aliases": github.get("aliases", []),
                "github_related_cves": github.get("related_cves", []),
                "github_top_pocs": github.get("top_pocs", []),
                "github_top_scanners": github.get("top_scanners", []),
                "github_top_exploits": github.get("top_exploits", []),
                "github_processed": True,
            },
        }
