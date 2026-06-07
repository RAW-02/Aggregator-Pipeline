import re

CVE_PATTERN = r"^CVE-\d{4}-\d+$"

class InputClassifier:

    @staticmethod
    def classify(user_input: str):
        user_input = user_input.strip()
        if re.match(CVE_PATTERN, user_input, re.IGNORECASE):
            return "cve"

        return "keyword"