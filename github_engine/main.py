import json
from github_engine.github_collector import GitHubCollector
from github_engine.enricher import enrich_repository
from github_engine.scorer import calculate_score
from github_engine.ranker import rank_repositories
from github_engine.alias_builder import AliasBuilder
from github_engine.deduplication_engine import deduplicate_repositories
from github_engine.correlation_engine import CorrelationEngine


def github_engine(user_query, debug=False):
    collector = GitHubCollector()

    repos = collector.search_repositories(
        user_query,
        limit=10,
    )

    repos = deduplicate_repositories(repos)

    for repo in repos:

        repo.readme = ""

        repo = enrich_repository(
            repo,
            user_query,
        )

        text = (f"{repo.repo_name} " f"{repo.description or ''}").lower()

        if "scanner" in text or "detect" in text:
            repo.repo_type = "Scanner"

        elif "exploit" in text:
            repo.repo_type = "Exploit"

        else:
            repo.repo_type = "PoC"

        repo.readme_score = 0

        repo.relevance_score = calculate_score(repo)

    repos = rank_repositories(repos)

    builder = AliasBuilder()

    for repo in repos:
        builder.process_repo(
            repo,
            user_query,
        )

    aliases = builder.build()

    engine = CorrelationEngine(
        repos,
        aliases,
        user_query,
    )

    record = engine.build_record()

    if debug:
        print(
            json.dumps(
                record,
                indent=4,
            )
        )

    return record
