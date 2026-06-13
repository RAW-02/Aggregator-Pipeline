from abc import ABC, abstractmethod

from storage.json_repo import JsonRepository


class BaseEnrichmentJob(ABC):

    def __init__(self):

        self.repository = JsonRepository()

    @property
    @abstractmethod
    def source(self):
        pass

    @abstractmethod
    def enrich_record(self, record):
        pass

    def run(self, limit=100):

        records = self.repository.get_pending(
            self.source,
            limit
        )

        print()
        print(f"{self.source.upper()} Pending :", len(records))
        print()

        updated = 0

        for record in records:

            try:

                self.enrich_record(record)

                updated += 1

            except Exception as e:

                print(e)

        print()

        print("Updated :", updated)