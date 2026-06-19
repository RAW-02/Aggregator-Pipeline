import re
from collections import defaultdict

STOP_WORDS = {
    "poc",
    "exploit",
    "scanner",
    "detector",
    "finder",
    "tool",
    "tools",
    "awesome",
    "list",
    "cve",
    "rce",
    "shell",
    "vulnerability",
    "vulnerable",
    "checker",
}
BAD_ALIAS_TERMS = {
    "app",
    "words",
    "proof",
    "concept",
    "ioc",
    "iocs",
    "scanner",
    "detector",
    "finder",
    "environment",
    "variables",
    "bypass",
    "vuln",
    "scan",
    "local",
    "secrets",
    "check",
    "checker",
}


class AliasBuilder:
    def __init__(self):
        self.alias_db = defaultdict(lambda: defaultdict(int))

    def normalize_alias(self, repo_name):
        repo_name = repo_name.split("/")[-1]
        repo_name = repo_name.lower()
        repo_name = re.sub(r"cve-\d{4}-\d+", "", repo_name)
        repo_name = repo_name.replace("-", " ")
        repo_name = repo_name.replace("_", " ")
        tokens = []

        for word in repo_name.split():
            if word not in STOP_WORDS and word not in BAD_ALIAS_TERMS and len(word) > 2:
                tokens.append(word)

        alias = " ".join(tokens)
        if len(alias.split()) > 2:
            return ""

        return alias

    def process_repo(self, repo, target_cve):
        alias = self.normalize_alias(repo.repo_name)

        if not alias:
            return

        if repo.cve_match:
            self.alias_db[alias][target_cve] += repo.relevance_score

    def build(self):
        final_aliases = {}
        for alias, cve_counts in self.alias_db.items():
            best_cve = max(cve_counts, key=cve_counts.get)
            final_aliases[alias] = {"cve": best_cve, "confidence": cve_counts[best_cve]}
        return final_aliases
