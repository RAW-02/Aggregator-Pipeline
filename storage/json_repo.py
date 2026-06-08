import json
import os
from dataclasses import asdict

from storage.vulnerability_repo import VulnerabilityRepository

class JsonRepository(VulnerabilityRepository):
    def __init__(self):
        self.db_path = "database/vulnerabilities.json"
        if not os.path.exists(self.db_path):
            with open(self.db_path, "w") as f:
                json.dump([], f, indent=4)

    def _load(self):
        with open(self.db_path, "r") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.db_path, "w") as f:
            json.dump(data, f, indent=4)

    def upsert(self, record):
        data = self._load()
        record_dict = asdict(record)
        updated = False

        for i, item in enumerate(data):
            if item["cve_id"] == record.cve_id:
                data[i] = record_dict
                updated = True
                break

        if not updated:
            data.append(record_dict)

        self._save(data)

    def bulk_upsert(self, records):
        for record in records:
            self.upsert(record)

    def get(self, cve_id):
        data = self._load()
        for item in data:
            if item["cve_id"] == cve_id:
                return item

        return None

    def delete(self, cve_id):
        data = self._load()
        data = [item for item in data if item["cve_id"] != cve_id]
        self._save(data)

    def search(self, keyword):
        data = self._load()
        keyword = keyword.lower()
        results = []

        for item in data:
            if (keyword in item["cve_id"].lower()
                or keyword in item["description"].lower()
                or any(keyword in p.lower() for p in item["products"])
            ):
                results.append(item)
        return results

    def get_all(self):
        return self._load()