from collections import Counter


class CorrelationEngine:
    def __init__(self, repos, aliases, primary_cve):
        self.repos = repos
        self.aliases = aliases
        self.primary_cve = primary_cve

    def get_related_cves(self):
        counter = Counter()

        for repo in self.repos:
            for cve in repo.detected_cves:
                if cve != self.primary_cve:
                    counter[cve] += 1

        results = []
        for cve, count in counter.most_common(5):
            results.append({"cve": cve, "count": count})
        return results

    def get_aliases(self):
        aliases = []
        for alias, data in self.aliases.items():
            if data["cve"] == self.primary_cve:
                aliases.append(alias)

        return aliases

    def get_top_pocs(self):
        pocs = []
        for repo in self.repos:
            if repo.repo_type == "PoC":
                pocs.append(repo)

        pocs.sort(key=lambda x: x.relevance_score, reverse=True)
        return pocs[:3]

    def get_top_scanners(self):
        scanners = []
        for repo in self.repos:
            if repo.repo_type == "Scanner":
                scanners.append(repo)

        scanners.sort(key=lambda x: x.relevance_score, reverse=True)
        return scanners[:3]

    def get_top_exploits(self):
        exploits = []
        for repo in self.repos:
            if repo.repo_type == "Exploit":
                exploits.append(repo)

        exploits.sort(key=lambda x: x.relevance_score, reverse=True)
        return exploits[:3]

    def repository_count(self):
        return len(self.repos)

    def build_record(self):
        return {
            "primary_cve": self.primary_cve,
            "repository_count": self.repository_count(),
            "aliases": self.get_aliases(),
            "related_cves": self.get_related_cves(),
            "top_pocs": [
                {
                    "name": repo.repo_name,
                    "url": repo.url,
                    "stars": repo.stars,
                    "score": repo.relevance_score,
                }
                for repo in self.get_top_pocs()
            ],
            "top_scanners": [
                {
                    "name": repo.repo_name,
                    "url": repo.url,
                    "stars": repo.stars,
                    "score": repo.relevance_score,
                }
                for repo in self.get_top_scanners()
            ],
            "top_exploits": [
                {
                    "name": repo.repo_name,
                    "url": repo.url,
                    "stars": repo.stars,
                    "score": repo.relevance_score,
                }
                for repo in self.get_top_exploits()
            ],
        }
