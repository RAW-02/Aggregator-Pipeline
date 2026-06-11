
import re

from storage.search_service import SearchService


class QueryResolver:

    def __init__(self):
        self.search = SearchService()

    # def resolve(self, query: str):
    def resolve(
        self,
        query: str,
        page: int = 1,
        size: int = 20
    ):

        q = query.lower().strip()

       

        # =====================================================
        # CVE
        # CVE-2021-44228
        # =====================================================

        if q.startswith("cve-"):
            return self.search.search_by_cve(
                query.upper(),
                page,
                size
            )

        # =====================================================
        # SEVERITY
        # critical
        # high
        # medium
        # low
        # severity:critical
        # severity critical
        # =====================================================

        if q == "critical":
            return self.search.search_by_severity(
                "CRITICAL",
                page,
                size
            )

        if q == "high":
            return self.search.search_by_severity(
                "HIGH",
                page,
                size
            )

        if q == "medium":
            return self.search.search_by_severity(
                "MEDIUM",
                page,
                size
            )

        if q == "low":
            return self.search.search_by_severity(
                "LOW",
                page,
                size
            )

        severity_match = re.search(
            r"severity\s*:?\s*(critical|high|medium|low)",
            q
        )

        if severity_match:
            return self.search.search_by_severity(
                severity_match.group(1).upper(),
                page,
                size
            )

        # =====================================================
        # CVSS
        # cvss > 7
        # cvss
        # cvss_score
        # =====================================================

        cvss_match = re.search(
            r"cvss\s*>\s*(\d+(\.\d+)?)",
            q
        )

        if cvss_match:
            return self.search.search_high_cvss(
                float(cvss_match.group(1)),
                page,
                size
            )

        if q in ["cvss", "cvss_score"]:
            return self.search.top_cvss(
                page,
                size
            )
        
        # =====================================================
        # EPSS
        # epss > 0.8
        # epss
        # epss_score
        # =====================================================

        epss_match = re.search(
            r"epss\s*>\s*(\d+(\.\d+)?)",
            q
        )

        if epss_match:
            return self.search.search_high_epss(
                float(epss_match.group(1)),
                page,
                size
            )

        if q in ["epss", "epss_score"]:
            return self.search.top_epss(
                page,
                size
            )

        # =====================================================
        # THREAT SCORE
        # threat > 80
        # threat
        # threat_score
        # =====================================================

        threat_match = re.search(
            r"threat\s*>\s*(\d+(\.\d+)?)",
            q
        )

        if threat_match:
            return self.search.search_high_threat(
                float(threat_match.group(1)),
                page,
                size
            )

        if q in ["threat", "threat_score"]:
            return self.search.top_threats(
                page,
                size
            )

        # =====================================================
        # CWE
        # cwe-79
        # cwe 79
        # =====================================================

        cwe_match = re.search(
            r"cwe[- ]?(\d+)",
            q
        )

        if cwe_match:
            return self.search.search_by_cwe(
            f"CWE-{cwe_match.group(1)}",
            page,
            size
        )

        # =====================================================
        # KEV
        # =====================================================

        if q == "kev":
            return self.search.search_kev(
                page,
                size
            )

        # =====================================================
        # EXPLOIT
        # =====================================================

        if q == "exploit":
            return self.search.search_exploitable(
                page,
                size
            )

        # =====================================================
        # PRODUCT SEARCH
        # ubuntu
        # vmware
        # oracle
        # windows
        # apache
        # =====================================================

        # =====================================================
        # PRODUCT SEARCH (dynamic)
        # =====================================================

        product_results = self.search.search_by_product(
            q,
            page,
            size
        )

        if product_results["hits"]["total"]["value"] > 0:
            return product_results

        # =====================================================
        # DEFAULT FULL TEXT SEARCH
        # =====================================================

        
        
        return self.search.full_text_search(
            query,
            page,
            size
        )