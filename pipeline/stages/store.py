from storage.json_repo import JsonRepository

class StorageStage:
    def __init__(self):
        self.repository = JsonRepository()

    def execute(self, record):
        self.repository.upsert(record)
        return record