import json
from dataclasses import asdict

from storage.elasticsearch_client import ElasticsearchClient
from storage.vulnerability_repo import VulnerabilityRepository



class ElasticsearchRepository(VulnerabilityRepository):

    def __init__(self):

        self.client = ElasticsearchClient().get_client()
        self.index_name = "vulnerabilities"

        if not self.client.indices.exists(index=self.index_name):

            with open(
                "storage/index_mapping.json",
                "r",
                encoding="utf-8"
            ) as f:

                mapping = json.load(f)

            self.client.indices.create(
                index=self.index_name,
                body=mapping
            )

    def upsert(self, record):

        return self.client.index(
            index=self.index_name,
            id=record.cve_id,
            document=asdict(record)
        )

    def bulk_upsert(self, records):

        for record in records:
            self.upsert(record)

    def get(self, cve_id):

        try:
            result = self.client.get(
                index=self.index_name,
                id=cve_id
            )

            return result["_source"]

        except:
            return None

    def delete(self, cve_id):

        try:
            self.client.delete(
                index=self.index_name,
                id=cve_id
            )
        except:
            pass

    def search(self, keyword):

        query = {
            "query": {
                "multi_match": {
                    "query": keyword,
                    "fields": [
                        "cve_id",
                        "description",
                        "products",
                        "severity",
                        "cwe"
                    ]
                }
            }
        }

        return self.client.search(
            index=self.index_name,
            body=query
        )
    
    def get_all(self):

        query = {
            "query": {
                "match_all": {}
            }
        }

        result = self.client.search(
            index=self.index_name,
            body=query,
            size=10000
        )

        return result["hits"]["hits"]

    def count(self):

        return self.client.count(
            index=self.index_name
        )["count"]