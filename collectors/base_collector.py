from abc import ABC, abstractmethod


class BaseCollector(ABC):

    @abstractmethod
    def fetch_by_id(self, identifier: str):
        """
        Fetch single record by CVE ID.
        """
        pass

    @abstractmethod
    def fetch_incremental(self, last_sync: str):
        """
        Fetch newly added or modified records after last_sync.
        """
        pass