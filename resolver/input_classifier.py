import re

CVE_PATTERN = r"^CVE-\d{4}-\d+$"    

class InputClassifier:
    @staticmethod
    def classify(query: str):
        query = query.strip()

        if re.match(CVE_PATTERN, query, re.IGNORECASE):
            return "cve"

        if len(query.split()) >= 2:
            return "product"

        return "keyword"