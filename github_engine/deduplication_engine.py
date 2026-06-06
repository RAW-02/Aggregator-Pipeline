def deduplicate_repositories(repos):
    unique = {}

    for repo in repos:
        unique[repo.repo_name] = repo

    return list(unique.values())