import json
import os

FAILED_DIRECTORY = "database/failed"
FAILED_FILE = os.path.join(FAILED_DIRECTORY, "failed_cves.json")

class FailedQueue:
    def __init__(self):
        os.makedirs(FAILED_DIRECTORY, exist_ok=True)
        if not os.path.exists(FAILED_FILE):
            with open(FAILED_FILE, "w", encoding="utf-8") as f:
                json.dump([], f)

    def _load(self):
        try:
            with open(FAILED_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return []
                return json.loads(content)

        except Exception:
            return []

    def add(self, cve, source, error):
        failed = self._load()
        failed.append({"cve": cve, "source": source, "error": str(error)})

        with open(FAILED_FILE, "w", encoding="utf-8") as f:
            json.dump(failed, f, indent=4)

    def get_all(self):
        return self._load()

    def clear(self):
        with open(FAILED_FILE, "w", encoding="utf-8") as f:
            json.dump([], f)