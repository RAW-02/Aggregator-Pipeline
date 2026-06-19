import json
import os

CHECKPOINT_DIRECTORY = "database/checkpoints"
CHECKPOINT_FILE = os.path.join(CHECKPOINT_DIRECTORY, "loader_checkpoint.json")


class CheckpointManager:
    def __init__(self):
        os.makedirs(CHECKPOINT_DIRECTORY, exist_ok=True)

        if not os.path.exists(CHECKPOINT_FILE):
            self.save(processed=0, last_cve=None)

    def save(self, processed, last_cve):
        with open(CHECKPOINT_FILE, "w", encoding="utf-8") as f:
            json.dump({"processed": processed, "last_cve": last_cve}, f, indent=4)

    def load(self):
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)

        except Exception:
            return {"processed": 0, "last_cve": None}
