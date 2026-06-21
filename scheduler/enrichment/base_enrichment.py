from abc import ABC, abstractmethod
from storage.opensearch_repository import OpenSearchRepository


class BaseEnrichmentJob(ABC):
    def __init__(self):
        self.repository = OpenSearchRepository()

    @property
    @abstractmethod
    def source(self):
        pass

    @abstractmethod
    def enrich_record(self, record):
        pass

    def run(self, limit=100):
        records = self.repository.get_pending(self.source, limit)

        print(f"{self.source.upper()} Pending :", len(records))
        
        if not records:
            return 0

        updates = []
        for record in records:
            try:
                update = self.enrich_record(record)
                if update:
                    updates.append(update)

            except Exception as e:
                print(e)

        self.repository.bulk_update(updates)

        print()
        print("Updated :", len(updates))

        return len(updates)
