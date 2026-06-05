from schemas.vulnerability import NVD_Model

class NVDDataNormalizer:

    @staticmethod
    def extract_cvss(metrics):
        for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if version not in metrics:
                continue

            metric = metrics[version][0]
            score = metric.get("cvssData", {}).get("baseScore", 0.0)
            severity = metric.get("baseSeverity") or metric.get("cvssData", {}).get("baseSeverity", "UNKNOWN")

            return score, severity

        return 0.0, "UNKNOWN"

    @staticmethod
    def extract_cwe(weaknesses):
        cwe_list = []
        for weakness in weaknesses:
            for desc in weakness.get("description",[]):
                value = desc.get("value", "")

                if (value and value != "NVD-CWE-noinfo"):
                    cwe_list.append(value)

        return sorted(set(cwe_list))

    @staticmethod
    def extract_products(configurations):
        products = set()
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):

                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")

                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        products.add(f"{vendor}:{product}")

        return sorted(products)

    def get_result(self, raw_vulnerability):
        cve = raw_vulnerability["cve"]
        score, severity = self.extract_cvss(cve.get("metrics", {}))

        return NVD_Model(
            cvss_score = score,
            severity = severity,
            cwe = self.extract_cwe(cve.get("weaknesses", [])),

            affected_products = self.extract_products(cve.get("configurations", []))
        )