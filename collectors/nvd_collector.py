from collectors.base_collector import BaseCollector
from collectors.nvd_dataset import NVDDataset


class NVDCollector(BaseCollector):

    def __init__(self):

        dataset = NVDDataset()

        self.cache = dataset.load()

    def fetch_by_id(self, cve_id):

        return self.cache.get(cve_id)

    def get_nvd_by_cve(self, cve):

        result = self.fetch_by_id(cve)

        if result is None:

            return {"cvss_score": None, "severity": None, "cwe": [], "products": []}

        return result

    def fetch_incremental(self, last_sync):

        return []
