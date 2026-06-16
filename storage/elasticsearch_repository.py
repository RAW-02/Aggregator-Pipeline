import json
from dataclasses import asdict, is_dataclass

from storage.elasticsearch_client import ElasticsearchClient
from storage.vulnerability_repo import VulnerabilityRepository
from opensearchpy.helpers import bulk

class ElasticsearchRepository(VulnerabilityRepository):

    def __init__(self):
        self.client = ElasticsearchClient().get_client()
        self.index_name = "vulnerabilities"

        if not self.client.indices.exists(index=self.index_name):
            with open("storage/index_mapping.json", "r", encoding="utf-8") as f:
                mapping = json.load(f)

            self.client.indices.create(
                index=self.index_name,
                body=mapping
            )

    def upsert(self, record):
        if is_dataclass(record):
            document = asdict(record)
            cve_id = record.cve_id
        else:
            document = record
            cve_id = record["cve_id"]

        return self.client.index(
            index=self.index_name,
            id=cve_id,
            document=document
        )

    def bulk_upsert(self, records):
        actions = []
        for record in records:
            if record is None:
                continue

            if is_dataclass(record):
                document = asdict(record)
                cve_id = record.cve_id
            else:
                document = record
                cve_id = record["cve_id"]

            actions.append({
                "_index": self.index_name,
                "_id": cve_id,
                "_source": document
            })

        if actions:
            bulk(self.client, actions, refresh=False)

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
                        "product_keywords",
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
        return self.client.count(index=self.index_name)["count"]
    
    def update_fields(self, cve_id, updates):
        
        self.client.update(
            index=self.index_name,
            id=cve_id,
            body={
                "doc": updates
            }
        )