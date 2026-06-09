class ValidationStage:

    def execute(self, record):
        if not record.cve_id:
            raise Exception("Missing CVE ID")

        if not record.description:
            record.description = "Unknown"

        if record.cvss_score is None:
            record.cvss_score = 0.0

        if record.epss_score is None:
            record.epss_score = 0.0

        return record