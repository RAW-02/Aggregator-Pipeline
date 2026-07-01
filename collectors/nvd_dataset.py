import json
import os

CACHE_PATH = "database/nvd_cache.json"

class NVDDataset:
    def load(self):

        if not os.path.exists(CACHE_PATH):
            raise Exception("NVD cache not found. Build cache first.")

        if os.path.getsize(CACHE_PATH) == 0:
            return {}

        with open(CACHE_PATH, "r", encoding="utf-8") as file:

            return json.load(file)