from collectors.nvd_collector import NVDCollector
from resolver.resolver_result import ResolverResult


class ProductResolver:
    def __init__(self):
        self.nvd = NVDCollector()

    def resolve(self, query):
        raw = self.nvd.fetch_NVD_data(query)
        candidates = []

        for vuln in raw["vulnerabilities"]:
            cve = vuln["cve"]
            candidates.append(

                ResolverResult(
                    cve_id=cve["id"],
                    score=70,
                    source="NVD",
                    matched_by="product",
                    published=cve["published"],
                    last_modified=cve["lastModified"]
                )
            )

        return candidates