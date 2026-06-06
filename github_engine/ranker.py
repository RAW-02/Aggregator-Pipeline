def rank_repositories(repos):
    return sorted(repos, key=lambda repo: repo.relevance_score, reverse=True)