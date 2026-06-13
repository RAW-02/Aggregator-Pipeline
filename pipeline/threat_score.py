class ThreatScore:
    @staticmethod
    def calculate(record):
        score = 0

        score += ((record.cvss_score or 0)/ 10) * 40

        if record.kev_status is True:
            score += 20

        score += (record.epss_score or 0) * 20

        if record.exploit_available:
            score += 10

        if record.github_repository_count > 0:
            score += 10

        return round(min(score, 100), 2)