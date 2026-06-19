from storage.opensearch_repository import OpenSearchRepository


class StorageStage:

    def __init__(self):
        self.repository = OpenSearchRepository()

    def execute(self, record):

        self.repository.upsert(record)

        return record
