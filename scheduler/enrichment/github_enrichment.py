from scheduler.enrichment.base_enrichment import BaseEnrichmentJob

from github_engine.main import github_engine


class GithubEnrichmentJob(BaseEnrichmentJob):
    source = "github"

    def enrich_record(self, record):
        print("GITHUB :", record["cve_id"])

        if (record.get("kev_status") or (record.get("cvss_score") or 0) >= 8 or (record.get("epss_score") or 0) >= 0.5):
            github = github_engine(record["cve_id"])
        else:
            github = {
                "repository_count": 0,
                "aliases": [],
                "related_cves": [],
                "top_pocs": [],
                "top_scanners": [],
                "top_exploits": []
            }

        return {
            "cve_id": record["cve_id"],
            "fields": {
                "github_repository_count": github["repository_count"],
                "github_aliases": github["aliases"],
                "github_related_cves": github["related_cves"],
                "github_top_pocs": github["top_pocs"],
                "github_top_scanners": github["top_scanners"],
                "github_top_exploits": github["top_exploits"],
                "github_processed": True
            }
        }