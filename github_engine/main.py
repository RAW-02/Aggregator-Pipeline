from github_engine.github_collector import GitHubCollector
from github_engine.enricher import enrich_repository
from github_engine.readme_fetcher import ReadmeFetcher
from github_engine.readme_analyzer import analyze_readme, classify_repo
from github_engine.scorer import calculate_score
from github_engine.ranker import rank_repositories
from github_engine.alias_builder import AliasBuilder
from github_engine.alias_resolver import AliasResolver
from github_engine.search_query_generator import generate_search_queries
from github_engine.deduplication_engine import deduplicate_repositories
from github_engine.query_classifier import classify_query
from github_engine.correlation_engine import CorrelationEngine
import json

def github_engine(user_query, debug=False):
    print("Github Resources Collecting ......")
    collector = GitHubCollector()
    fetcher = ReadmeFetcher()

    query_info = classify_query(user_query)

    search_queries = generate_search_queries(user_query, query_info["type"])

    all_repos = []
    for query in search_queries:
        repos = collector.search_repositories(query)
        all_repos.extend(repos)

    repos = deduplicate_repositories(all_repos)

    for ind in range(len(repos)):
        repo = repos[ind]
        repo.readme = fetcher.fetch_readme(repo.repo_name)
        repo = enrich_repository(repo, user_query)
        readme_analyzer_result = analyze_readme(repo.readme)
        repo.repo_type = classify_repo(repo.repo_name, readme_analyzer_result)
        repo.readme_score = readme_analyzer_result["score"]
        repo.relevance_score = calculate_score(repo)

    repos = rank_repositories(repos)

    builder = AliasBuilder()
    for repo in repos:
        builder.process_repo(repo, user_query)
    aliases = builder.build()

    engine = CorrelationEngine(repos, aliases, user_query)
    record = engine.build_record()
    
    if debug:
        print(json.dumps(record, indent=4))

    return record