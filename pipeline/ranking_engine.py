from datetime import datetime

class RankingEngine:

    @staticmethod
    def rank(records, sort_by="threat_score"):
        if sort_by == "threat_score":
            return sorted(records, key=lambda x: x.threat_score, reverse=True)

        if sort_by == "cvss":
            return sorted(records, key=lambda x: x.cvss_score, reverse=True)

        if sort_by == "epss":
            return sorted(records, key=lambda x: x.epss_score, reverse=True)

        if sort_by == "published_date":
            return sorted(records, key=lambda x: datetime.strptime(x.published_date, "%Y-%m-%d"), reverse=True)

        return records