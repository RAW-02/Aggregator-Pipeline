from github_engine.main import github_engine
from pipeline.threat_score import ThreatScore


class GithubPipeline:

    def process(self, record):

        github = github_engine(record.cve_id)

        record.github_repository_count = github["repository_count"]

        record.github_aliases = github["aliases"]

        record.github_related_cves = github["related_cves"]

        record.github_top_pocs = github["top_pocs"]

        record.github_top_scanners = github["top_scanners"]

        record.github_top_exploits = github["top_exploits"]

        record.github_processed = True

        record.threat_score = ThreatScore.calculate(record)

        return record
