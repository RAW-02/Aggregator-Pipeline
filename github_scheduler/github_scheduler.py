from storage.json_repo import JsonRepository
from github_scheduler.github_runner import GithubRunner

repository = JsonRepository()
runner = GithubRunner()

def github_sync():
    records = repository.get_unprocessed_github()
    records = records[:100]
    updated = runner.run(records)
    repository.bulk_upsert(updated)

    print(f"Github updated {len(updated)} records")