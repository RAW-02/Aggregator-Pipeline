
import re

from storage.search_service import SearchService


class QueryResolver:

    def __init__(self):
        self.search = SearchService()

    def resolve(self, query: str):

        q = query.lower().strip()

        # CVE Search
        if q.startswith("cve-"):
            return self.search.search_by_cve(query.upper())

        # CVSS Search
        cvss_match = re.search(r"cvss\s*>\s*(\d+(\.\d+)?)", q)
        if cvss_match:
            score = float(cvss_match.group(1))
            return self.search.search_high_cvss(score)

        # EPSS Search
        epss_match = re.search(r"epss\s*>\s*(\d+(\.\d+)?)", q)
        if epss_match:
            score = float(epss_match.group(1))
            return self.search.search_high_epss(score)

        # Threat Score
        threat_match = re.search(
            r"threat\s*>\s*(\d+(\.\d+)?)",
            q
        )

        if threat_match:
            score = float(threat_match.group(1))
            return self.search.search_high_threat(score)

        # KEV
        if "kev" in q:
            return self.search.search_kev()

        # Exploit
        if "exploit" in q:
            return self.search.search_exploitable()

        # Severity
        if q == "critical":
            return self.search.search_by_severity("CRITICAL")

        if q == "high":
            return self.search.search_by_severity("HIGH")

        if q == "medium":
            return self.search.search_by_severity("MEDIUM")

        if q == "low":
            return self.search.search_by_severity("LOW")

        # Default
        return self.search.full_text_search(query)