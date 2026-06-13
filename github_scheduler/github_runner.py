from concurrent.futures import ThreadPoolExecutor
from github_scheduler.github_worker import GithubWorker

class GithubRunner:
    def __init__(self):
        self.worker = GithubWorker()

    def run(self, records):
        with ThreadPoolExecutor(max_workers=2) as executor:
            return list(filter(None, executor.map(self.worker.process, records)))