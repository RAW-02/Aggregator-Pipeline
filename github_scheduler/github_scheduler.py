from storage.opensearch_repository import OpenSearchRepository
from github_scheduler.github_runner import GithubRunner

repository = OpenSearchRepository()
runner = GithubRunner()

def github_sync():
    records = repository.get_unprocessed_github()
    records = records[:100]
    updated = runner.run(records)
    repository.bulk_upsert(updated)

    print(f"Github updated {len(updated)} records")