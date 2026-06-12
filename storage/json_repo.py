import json
import os
from dataclasses import asdict, is_dataclass
from storage.vulnerability_repo import VulnerabilityRepository

class JsonRepository(VulnerabilityRepository):
    def __init__(self):
        self.db_directory = "database/vulnerabilities"
        os.makedirs(self.db_directory, exist_ok=True)

    def _file_path(self, cve_id):
        return os.path.join(self.db_directory, f"{cve_id}.json")

    def upsert(self, record):
        if record is None:
            return
        if is_dataclass(record):
            data = asdict(record)
        else:
            data = record

        path = self._file_path(data["cve_id"])
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

    def bulk_upsert(self, records):
        print("Bulk upserting on JsonRepository On Working ..........")
        for record in records:
            self.upsert(record)

    def get(self, cve_id):
        path = self._file_path(cve_id)

        if not os.path.exists(path):
            return None

        with open(path, "r") as f:
            return json.load(f)

    def delete(self, cve_id):
        path = self._file_path(cve_id)
        if os.path.exists(path):
            os.remove(path)

    def get_all(self):
        records = []
        for filename in os.listdir(self.db_directory):
            if filename.endswith(".json"):
                with open(
                    os.path.join(self.db_directory, filename), "r") as f:
                    records.append(json.load(f))

        return records

    def get_all_cve_ids(self):
        ids = []
        for filename in os.listdir(self.db_directory):
            if filename.endswith(".json"):
                ids.append(filename.replace(".json", ""))

        return ids

    def search(self, keyword):
        keyword = keyword.lower()

        results = []
        for record in self.get_all():
            if (keyword in record["cve_id"].lower()
                or keyword in record["description"].lower()
                or any(keyword in product.lower() for product in record.get("products", []))):
                
                results.append(record)

        return results
    
    def get_unprocessed_github(self):
        records = self.get_all()

        result = []
        for record in records:
            if not record.get("github_processed", False):
                result.append(record)

        return result
    

    def update(self, cve_id, updates):
        record = self.get(cve_id)

        if record is None:
            return

        if is_dataclass(updates):
            updates = asdict(updates)

        record.update(updates)
        path = self._file_path(cve_id)

        with open(path, "w") as f:
            json.dump(record, f, indent=4)

    def get_unprocessed_nvd(self):
        records = self.get_all()
        result = []

        for record in records:
            if not record.get("nvd_processed", False):
                result.append(record)

        return result