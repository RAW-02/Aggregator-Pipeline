from readme_fetcher import ReadmeFetcher

fetcher = ReadmeFetcher()

def enrich_readme(repo):
    repo.readme = (fetcher.fetch_readme(repo.repo_name))
    return repo