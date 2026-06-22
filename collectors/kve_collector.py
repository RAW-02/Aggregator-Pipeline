from collectors.base_collector import BaseCollector
from collectors.kev_dataset import KEVDataset


class KEVCollector(BaseCollector):
    def __init__(self):
        dataset = KEVDataset()
        self.kev_set = dataset.load()

    def is_known_exploited(self, cve_id):
        return cve_id in self.kev_set

    def fetch_incremental(self, last_sync):
        # Future implementation
        return []
