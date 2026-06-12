import time

from github_scheduler.github_pipeline import GithubPipeline


class GithubWorker:
    def __init__(self):
        self.pipeline = GithubPipeline()

    def process(self, record):
        try:
            updated = self.pipeline.process(record)
            time.sleep(2)
            return updated

        except Exception as e:
            print(e)
            return None