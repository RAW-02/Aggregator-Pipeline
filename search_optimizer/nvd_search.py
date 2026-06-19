class NVDSearchOptimizer:
    def search_vulnerabilities(
        self, vulnerabilities, severity=None, cwe=None, product=None, min_cvss=None
    ):
        results = []
        for vuln in vulnerabilities:
            if severity:
                if vuln.severity.upper() != severity.upper():
                    continue

            if cwe:
                if cwe not in vuln.cwe:
                    continue

            if product:
                matched = any(
                    product.lower() in p.lower() for p in vuln.affected_products
                )
                if not matched:
                    continue

            if min_cvss:
                if vuln.cvss_score < min_cvss:
                    continue

            results.append(vuln)
        return results
