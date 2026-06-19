import re

CVE_REGEX = r"CVE-\d{4}-\d{4,7}"


def enrich_repository(repo, target_cve):
    combined_text = " ".join(
        [str(repo.repo_name), str(repo.description), str(repo.readme)]
    )

    detected = extract_cves(combined_text)
    repo.detected_cves = detected

    if target_cve and target_cve.upper() in detected:
        repo.cve_match = True

    return repo


def extract_cves(text):
    if not text:
        return []
    matches = re.findall(CVE_REGEX, text, flags=re.IGNORECASE)
    return list(set(map(str.upper, matches)))
