from dataclasses import asdict

from elasticsearch.helpers import bulk
from storage.elastic_client import ElasticClient
from storage.vulnerability_repo import VulnerabilityRepository
from storage.mappings import INDEX_MAPPING, INDEX_NAME

class ElasticRepository(VulnerabilityRepository):
    def __init__(self):
        self.client = ElasticClient.get_client()

    def create_index(self):
        if not self.client.indices.exists(index=INDEX_NAME):
            self.client.indices.create(
                index=INDEX_NAME,
                body=INDEX_MAPPING
            )

    def upsert(self, record):
        self.client.index(
            index=INDEX_NAME,
            id=record.cve_id,
            document=asdict(record)
        )

    def bulk_upsert(self, records):
        actions = []

        for record in records:
            actions.append(
                {
                    "_index": INDEX_NAME,
                    "_id": record.cve_id,
                    "_source": asdict(record)
                }
            )

        bulk(self.client, actions)

    def get(self, cve_id):
        result = self.client.get(
            index=INDEX_NAME,
            id=cve_id
        )
        return result["_source"]

    def delete(self, cve_id):
        self.client.delete(
            index=INDEX_NAME,
            id=cve_id
        )

    def search(self, query):
        body = {
            "query": {
                "multi_match": {
                    "query": query,
                    "fields": [
                        "cve_id",
                        "description",
                        "products",
                        "github_aliases"
                    ]
                }
            }
        }

        result = self.client.search(index=INDEX_NAME, body=body)

        return result["hits"]["hits"]