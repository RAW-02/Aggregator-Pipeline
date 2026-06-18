class ThreatScoreCalculator:

    @staticmethod
    def calculate(record):
        cvss = min(record.get("cvss_score") or 0, 10) * 5

        epss = min(record.get("epss_score") or 0, 1) * 25

        kev = 15 if record.get("kev_status") else 0

        exploit = 5 if record.get("exploit_available") else 0

        github = (min(record.get("github_repository_count") or 0, 10) / 10) * 5

        score = (cvss + epss + kev + exploit + github)

        return round(score, 2)