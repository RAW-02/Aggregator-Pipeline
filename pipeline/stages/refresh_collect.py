from storage.elasticsearch_repository import ElasticsearchRepository

from collectors.nvd_collector import NVDCollector
from collectors.epss_collector import EPSSCollector
from collectors.kve_collector import KEVCollector
from collectors.exploitdb_collector import ExploitDBCollector

from github_engine.main import github_engine

from schemas.vulnerability import VulnerabilityRecord


class RefreshCollectStage:
    def __init__(self):
        self.repository = ElasticsearchRepository()
        self.nvd = NVDCollector()
        self.epss = EPSSCollector()
        self.kev = KEVCollector()
        self.exploit = ExploitDBCollector()

    def execute(self, cve):
        data = self.repository.get(cve)
        if data is None:
            return {
                "status": "create",
                "cve": cve
            }

        record = VulnerabilityRecord(**data)

        nvd = self.nvd.fetch_by_id(cve)
        if nvd:
            record.cvss_score = nvd.cvss_score
            record.severity = nvd.severity
            record.cwe = nvd.cwe
            record.products = nvd.affected_products

        record.kev_status = self.kev.fetch_by_id(cve)["kev_status"]

        record.epss_score = self.epss.fetch_by_id(cve)["epss_score"]

        exploit = self.exploit.fetch_by_id(record.description)
        record.exploit_available = exploit["exploit_available"]
        record.exploit_count = exploit["exploit_count"]
        record.exploits = exploit["exploits"]

        github = github_engine(cve)
        record.github_repository_count = github["repository_count"]
        record.github_aliases = github["aliases"]
        record.github_related_cves = github["related_cves"]
        record.github_top_pocs = github["top_pocs"]
        record.github_top_scanners = github["top_scanners"]
        record.github_top_exploits = github["top_exploits"]

        return {
            "status": "refresh",
            "record": record
        }