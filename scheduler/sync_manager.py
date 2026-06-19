import json
import os
from datetime import datetime
from scheduler.constant import SYNC_DIRECTORY


class SyncManager:
    def __init__(self):
        os.makedirs(SYNC_DIRECTORY, exist_ok=True)

    def _file(self, source):
        return os.path.join(SYNC_DIRECTORY, f"{source}.json")

    def get_last_sync(self, source):
        file = self._file(source)
        if not os.path.exists(file):
            return None

        with open(file, "r") as f:
            data = json.load(f)

        return data.get("last_sync")

    def update_last_sync(self, source):
        file = self._file(source)

        with open(file, "w") as f:
            json.dump(
                {"last_sync": datetime.now(datetime.UTC).isoformat()}, f, indent=4
            )
