from inventory.models import (
    InventoryComponent,
    ComponentReport,
    MatchedVulnerability,
)


class InventoryMatcher:

    def __init__(self, search_service):
        self.search_service = search_service

    def build_vulnerability(self, hit):
        return MatchedVulnerability(
            cve_id=hit.get("cve_id"),
            severity=hit.get("severity", "UNKNOWN"),
            cvss_score=hit.get("cvss_score", 0),
            epss_score=hit.get("epss_score", 0),
            threat_score=hit.get("threat_score", 0),
            kev=hit.get("kev", False),
            exploit_available=hit.get("exploit_available", False),
        )

    def match(
        self,
        component: InventoryComponent,
    ) -> ComponentReport:
        response = self.search_service.search_inventory_component(
            vendor=component.vendor, product=component.product, page=1, size=500
        )

        vulnerabilities = []
        highest_score = 0.0
        hits = response.get("results", [])

        for hit in hits:
            vulnerability = self.build_vulnerability(hit)
            vulnerabilities.append(vulnerability)

            highest_score = max(highest_score, vulnerability.threat_score)

        return ComponentReport(
            host=component.host,
            vendor=component.vendor,
            product=component.product,
            version=component.version,
            highest_threat_score=highest_score,
            vulnerabilities=vulnerabilities,
        )
