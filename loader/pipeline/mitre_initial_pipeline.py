from collectors.mitre_collector import MITRECollector
from schemas.vulnerability import VulnerabilityRecord


class MitreInitialPipeline:

    def __init__(self):
        self.mitre = MITRECollector()

    def run(self, mitre_json):

        mitre = self.mitre.normalize(mitre_json)

        record = VulnerabilityRecord()

        record.cve_id = mitre["cve_id"]
        record.description = mitre["description"]
        record.published_date = mitre["published_date"]
        record.last_modified = mitre["last_modified"]
        record.references = mitre["references"]

        record.nvd_processed = False
        record.epss_processed = False
        record.kev_processed = False
        record.github_processed = False
        record.exploitdb_processed = False

        return record
