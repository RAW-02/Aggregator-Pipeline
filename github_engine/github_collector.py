import requests
from github_engine.config import GITHUB_TOKEN
from github_engine.models import RepoInfo

class GitHubCollector:
    GITHUB_REPO_URL = "https://api.github.com/search/repositories"

    def search_repositories(self, query, limit=15):
        headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}

        params = {"q": query, "sort": "stars", "order": "desc", "per_page": limit}

        response = requests.get(self.GITHUB_REPO_URL, headers=headers, params=params)
        response.raise_for_status()

        data = response.json()
        repos = []

        for item in data.get("items", []):
            repo = RepoInfo(
                repo_name=item["full_name"],
                description=item.get("description", ""),
                stars=item["stargazers_count"],
                forks=item["forks_count"],
                updated_at=item["updated_at"],
                url=item["html_url"]
            )
            repos.append(repo)

        return repos