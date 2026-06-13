# import json
# import os
# from dataclasses import asdict, is_dataclass
# from storage.vulnerability_repo import VulnerabilityRepository
# from storage.index.pending_index import PendingIndex

# class JsonRepository(VulnerabilityRepository):
#     def __init__(self):
#         self.db_directory = "database/vulnerabilities"
#         os.makedirs(self.db_directory, exist_ok=True)
#         self.pending = PendingIndex()

#     def _file_path(self, cve_id):
#         return os.path.join(self.db_directory, f"{cve_id}.json")

#     def upsert(self, record):
#         if record is None:
#             return
        
#         if is_dataclass(record):
#             data = asdict(record)
#         else:
#             data = record

#         path = self._file_path(data["cve_id"])
#         with open(path, "w", encoding="utf-8") as f:
#             json.dump(data, f, indent=4)

#         sources = ["nvd", "github", "epss"]
#         for source in sources:
#             processed = data.get(f"{source}_processed", False)
#             if processed:
#                 self.pending.remove(source, data["cve_id"])
#             else:
#                 self.pending.add(source, data["cve_id"])

#     def bulk_upsert(self, records):
#         print("Bulk upserting...")
#         for record in records:
#             self.upsert(record)

#         self.pending.flush()

#     def get(self, cve_id):
#         path = self._file_path(cve_id)
#         if not os.path.exists(path):
#             return None

#         with open(path, "r") as f:
#             return json.load(f)

#     def delete(self, cve_id):
#         path = self._file_path(cve_id)
#         if os.path.exists(path):
#             os.remove(path)

#         for source in ["nvd", "github", "epss"]:
#             self.pending.remove(source, cve_id)

#         self.pending.flush()

#     def get_all(self):
#         records = []
#         for filename in os.listdir(self.db_directory):
#             if filename.endswith(".json"):
#                 with open(
#                     os.path.join(self.db_directory, filename), "r") as f:
#                     records.append(json.load(f))

#         return records

#     def get_all_cve_ids(self):
#         ids = []
#         for filename in os.listdir(self.db_directory):
#             if filename.endswith(".json"):
#                 ids.append(filename.replace(".json", ""))

#         return ids

#     def search(self, keyword):
#         keyword = keyword.lower()

#         results = []
#         for record in self.get_all():
#             if (keyword in record["cve_id"].lower()
#                 or keyword in record["description"].lower()
#                 or any(keyword in product.lower() for product in record.get("products", []))):
                
#                 results.append(record)

#         return results    
    
#     def get_pending(self, source, limit=100):
#         ids = list(self.pending.load(source))[:limit]
#         records = []

#         for cve in ids:
#             record = self.get(cve)
#             if record is not None:
#                 records.append(record)

#         return records
    
#     def update_fields(self, cve_id, updates):
#         record = self.get(cve_id)
#         if record is None:
#             return

#         if is_dataclass(updates):
#             updates = asdict(updates)

#         record.update(updates)
#         self.upsert(record)

import json
import os
from dataclasses import asdict, is_dataclass

from storage.vulnerability_repo import VulnerabilityRepository
from storage.index.pending_index import PendingIndex
from logs.logger import logger

class JsonRepository(VulnerabilityRepository):

    def __init__(self):

        self.base_directory = "database/vulnerabilities"
        os.makedirs(self.base_directory, exist_ok=True)

        self.pending = PendingIndex()

    def _directory(self, cve_id):

        year = cve_id.split("-")[1]

        directory = os.path.join(
            self.base_directory,
            year
        )

        os.makedirs(directory, exist_ok=True)

        return directory

    def _file_path(self, cve_id):

        return os.path.join(

            self._directory(cve_id),

            f"{cve_id}.json"

        )

    # ---------------------------------------------------------

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

        # update pending indexes

        for source in [

            "nvd",

            "epss",

            "kev",

            "exploitdb",

            "github"

        ]:

            processed = data.get(
                f"{source}_processed",
                False
            )

            if processed:
                self.pending.remove(
                    source,
                    data["cve_id"]
                )

            else:
                self.pending.add(
                    source,
                    data["cve_id"]
                )

    # ---------------------------------------------------------

    def bulk_upsert(self, records):

        logger.info("Bulk Upserting %s records", len(records))

        for record in records:
            self.upsert(record)

    # ---------------------------------------------------------

    def get(self, cve_id):

        path = self._file_path(cve_id)

        if not os.path.exists(path):
            return None

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    # ---------------------------------------------------------

    def delete(self, cve_id):

        path = self._file_path(cve_id)

        if os.path.exists(path):
            os.remove(path)

    # ---------------------------------------------------------

    def get_all(self):

        records = []

        for year in os.listdir(self.base_directory):

            year_path = os.path.join(
                self.base_directory,
                year
            )

            if not os.path.isdir(year_path):
                continue

            for filename in os.listdir(year_path):

                if filename.endswith(".json"):

                    with open(

                        os.path.join(year_path, filename),

                        "r",

                        encoding="utf-8"

                    ) as f:

                        records.append(json.load(f))

        return records

    # ---------------------------------------------------------

    def get_all_cve_ids(self):

        ids = []

        for year in os.listdir(self.base_directory):

            year_path = os.path.join(
                self.base_directory,
                year
            )

            if not os.path.isdir(year_path):
                continue

            for filename in os.listdir(year_path):

                if filename.endswith(".json"):

                    ids.append(

                        filename.replace(
                            ".json",
                            ""
                        )

                    )

        return ids

    # ---------------------------------------------------------

    def search(self, keyword):

        keyword = keyword.lower()

        results = []

        for record in self.get_all():

            if (

                keyword in record["cve_id"].lower()

                or

                keyword in record["description"].lower()

                or

                any(

                    keyword in product.lower()

                    for product in record.get(

                        "products",

                        []

                    )

                )

            ):

                results.append(record)

        return results

    # ---------------------------------------------------------

    def get_pending(self, source, limit=100):

        ids = self.pending.load(source)

        records = []

        for cve in ids[:limit]:

            record = self.get(cve)

            if record:

                records.append(record)

        return records

    # ---------------------------------------------------------

    def update_fields(self, cve_id, updates):

        record = self.get(cve_id)

        if record is None:
            return

        if is_dataclass(updates):
            updates = asdict(updates)

        record.update(updates)

        self.upsert(record)

    # ---------------------------------------------------------

    def get_unprocessed_nvd(self, limit=100):

        return self.get_pending("nvd", limit)

    def get_unprocessed_epss(self, limit=100):

        return self.get_pending("epss", limit)

    def get_unprocessed_kev(self, limit=100):

        return self.get_pending("kev", limit)

    def get_unprocessed_exploitdb(self, limit=100):

        return self.get_pending("exploitdb", limit)

    def get_unprocessed_github(self, limit=100):

        return self.get_pending("github", limit)