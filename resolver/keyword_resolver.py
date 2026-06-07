from collectors.nvd_collector import NVDCollector


class KeywordResolver:

    def __init__(self):
        self.nvd = NVDCollector()

    def resolve(self, keyword):
        raw = self.nvd.fetch_NVD_data(keyword)
        results = []

        seen = set()
        for vuln in raw.get("vulnerabilities", []):
            cve = vuln["cve"]
            cve_id = cve.get("id")

            if cve_id in seen:
                continue

            seen.add(cve_id)

            results.append({
                "cve_id": cve_id,
                "published": cve.get("published", ""),
                "last_modified": cve.get("lastModified", "")

            })

        results.sort(key=lambda x: x["published"],reverse=True)

        return results