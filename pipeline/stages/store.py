from storage.elasticsearch_repository import ElasticsearchRepository

class StorageStage:

    def __init__(self):
        self.repository = ElasticsearchRepository()

    def execute(self, record):

        self.repository.upsert(record)

        return record