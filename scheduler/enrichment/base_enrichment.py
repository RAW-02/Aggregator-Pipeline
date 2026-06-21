from abc import ABC, abstractmethod
from storage.opensearch_repository import OpenSearchRepository
from concurrent.futures import ThreadPoolExecutor
from config.settings import THREAD_POOL_SIZE


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

        with ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE) as executor:
            results = list(executor.map(self.safe_enrich, records))

        updates = [r for r in results if r]

        self.repository.bulk_update(updates)

        print()
        print("Updated :", len(updates))

        return len(updates)

    def safe_enrich(self, record):
        try:
            return self.enrich_record(record)
        except Exception as e:
            print(e)
            return None
