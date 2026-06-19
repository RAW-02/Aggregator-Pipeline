import requests
from github_engine.config import GITHUB_TOKEN
from github_engine.models import RepoInfo
from network.rate_limiter import RateLimiter
from network.retry import RetryManager


class GitHubCollector:
    GITHUB_REPO_URL = "https://api.github.com/search/repositories"
    limiter = RateLimiter(0.5)

    def _request(self, headers, params):
        response = requests.get(
            self.GITHUB_REPO_URL, headers=headers, params=params, timeout=30
        )
        response.raise_for_status()
        return response

    def search_repositories(self, query, limit=10):
        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "UniVulner",
        }
        params = {"q": query, "sort": "stars", "order": "desc", "per_page": limit}
        self.limiter.wait()

        response = RetryManager.execute(lambda: self._request(headers, params))

        data = response.json()
        repos = []

        for item in data.get("items", []):
            repo = RepoInfo(
                repo_name=item["full_name"],
                description=item.get("description", ""),
                stars=item["stargazers_count"],
                forks=item["forks_count"],
                updated_at=item["updated_at"],
                url=item["html_url"],
            )
            repos.append(repo)

        return repos
