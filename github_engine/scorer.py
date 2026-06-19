from datetime import datetime, timezone

BAD_TERMS = ["awesome", "list", "collection"]


def calculate_score(repo):
    score = 0
    if repo.cve_match:
        score += 50

    if repo.detected_cves:
        score += 30

    if repo.repo_type == "PoC":
        score += 30

    elif repo.repo_type == "Exploit":
        score += 35

    elif repo.repo_type == "Scanner":
        score += 15

    if repo.repo_type == "Unknown":
        score -= 20

    repo_name = repo.repo_name.lower()

    for term in BAD_TERMS:
        if term in repo_name:
            score -= 40

    score += min(repo.stars // 50, 20)
    score += min(repo.forks // 20, 10)
    score += recent_update_score(repo.updated_at)
    score += min(repo.readme_score * 5, 25)

    return score


def recent_update_score(updated_at):
    updated = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ")
    updated = updated.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - updated).days

    if age_days < 180:
        return 10

    elif age_days < 365:
        return 5

    return 0
