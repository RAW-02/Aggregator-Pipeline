from scheduler.enrichment.base_enrichment import BaseEnrichmentJob

from github_engine.main import github_engine


class GithubEnrichmentJob(BaseEnrichmentJob):

    source = "github"

    def enrich_record(self, record):

        print("GITHUB :", record["cve_id"])

        github = github_engine(

            record["cve_id"]

        )

        self.repository.update_fields(

            record["cve_id"],

            {

                "github_repository_count": github["repository_count"],

                "github_aliases": github["aliases"],

                "github_related_cves": github["related_cves"],

                "github_top_pocs": github["top_pocs"],

                "github_top_scanners": github["top_scanners"],

                "github_top_exploits": github["top_exploits"],

                "github_processed": True

            }

        )