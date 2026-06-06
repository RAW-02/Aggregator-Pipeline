class RepoInfo:

    def __init__(
        self,
        repo_name,
        description,
        stars,
        forks,
        updated_at,
        url
    ):
        self.repo_name = repo_name
        self.description = description or ""
        self.stars = stars
        self.forks = forks
        self.updated_at = updated_at
        self.url = url
        
        self.detected_cves = []
        self.cve_match = False

        self.readme = ""
        self.repo_type = "Unknown"
        self.relevance_score = 0

    def __repr__(self):
        return (
            f"\nRepo_Name: {self.repo_name}\n"
            f"Stars ⭐: {self.stars}\n"
            f"Forks: {self.forks}\n"
            f"URL: {self.url}\n"
            f"Detected CVEs: {self.detected_cves}\n"
            f"CVE Match: {self.cve_match}\n"
            f"Repo Type: {self.repo_type}\n"
            f"README Score: {self.readme_score}\n"
            f"Relevance Score: {self.relevance_score}\n"
        )
    

    def to_dict(self):
        return {
            "repo_name": self.repo_name,
            "stars ⭐": self.stars,
            # "forks": self.forks,
            # "url": self.url,
            "detected_cves": self.detected_cves,
            "cve_match": self.cve_match
        }