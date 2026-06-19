EXPLOIT_KEYWORDS = [
    "exploit",
    "proof of concept",
    "poc",
    "payload",
    "shell",
    "rce",
    "remote code execution",
    "vulnerability",
]


def analyze_readme(text):
    text = text.lower()
    score = 0
    found = []

    for keyword in EXPLOIT_KEYWORDS:
        if keyword in text:
            score += 1
            found.append(keyword)

    return {"score": score, "keywords": found}


def classify_repo(repo_name, analysis):
    keywords = repo_name.lower() + " " + " ".join(analysis["keywords"]).lower()
    if (
        "scanner" in keywords
        or "scan" in keywords
        or "detector" in keywords
        or "finder" in keywords
    ):
        return "Scanner"

    if "proof of concept" in keywords or "poc" in keywords:
        return "PoC"

    if "exploit" in keywords:
        return "Exploit"

    return "Unknown"
