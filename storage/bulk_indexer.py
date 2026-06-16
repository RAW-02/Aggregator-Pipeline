from storage.opensearch_repository import OpenSearchRepository


class BulkIndexer:

    def __init__(self):

        self.repository = OpenSearchRepository()

    def save(self, records):

        self.repository.bulk_upsert(records)