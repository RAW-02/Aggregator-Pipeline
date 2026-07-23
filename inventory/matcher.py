from inventory.models import (
    InventoryComponent,
    ComponentReport,
    MatchedVulnerability,
)
from schemas.vulnerability import AffectedProduct
from inventory.version_comparator import VersionComparator


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
            kev=hit.get("kev_status", False),
            exploit_available=hit.get("exploit_available", False),
        )

    def match(
        self,
        component: InventoryComponent,
    ) -> ComponentReport:
        response = self.search_service.search_inventory_component(
            vendor=component.vendor, product=component.product, page=1, size=500
        )

        print("=" * 60)
        print(f"Component: {component.vendor}:{component.product}")
        print(f"Total Hits: {response['hits']['total']}")
        print("=" * 60)

        vulnerabilities = []
        highest_score = 0.0
        hits = response.get("hits", {}).get("hits", [])

        for hit in hits:
            source = hit.get("_source", {})

            print("=" * 80)
            print("Component Version :", component.version)
            print("CVE :", source.get("cve_id"))
            print("Affected Products :", source.get("affected_products"))

            match = self.is_version_match(component, source)

            print("Version Match :", match)

            if not match:
                continue

            vulnerability = self.build_vulnerability(source)

            vulnerabilities.append(vulnerability)

            highest_score = max(
                highest_score,
                vulnerability.threat_score,
            )

        return ComponentReport(
            host=component.host,
            vendor=component.vendor,
            product=component.product,
            version=component.version,
            highest_threat_score=highest_score,
            vulnerabilities=vulnerabilities,
        )

    def is_version_match(
        self,
        component: InventoryComponent,
        source: dict,
    ) -> bool:

        affected_products = source.get("affected_products", [])
        if not affected_products:
            return True

        for product in affected_products:
            affected = AffectedProduct(**product)
            if affected.vendor.lower() != component.vendor.lower():
                continue

            if affected.product.lower() != component.product.lower():
                continue

            if VersionComparator.is_vulnerable(
                component.version,
                affected,
            ):
                return True

        return False
