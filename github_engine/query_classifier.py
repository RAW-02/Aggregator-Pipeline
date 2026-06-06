import re

CATEGORY_KEYWORDS = {"rce", "remote code execution", "xss", "sql injection", "privilege escalation", "csrf", "ssrf", "directory traversal", "lfi", "rfi", "injection"}

def classify_query(query):
    query = query.strip()

    # Input Case 1: CVE
    if re.match(r"^CVE-\d{4}-\d+$", query, re.IGNORECASE):
        return {"type": "cve", "value": query.upper()}

    query_lower = query.lower()

    # Input Case 2: Category
    if query_lower in CATEGORY_KEYWORDS:
        return {"type": "category", "value": query}

    # Input Case 3: product or vulnerability
    if len(query.split()) <= 2:
        return {"type": "product_or_vulnerability", "value": query}

    # Input Case 4: Other
    return {"type": "description", "value": query}