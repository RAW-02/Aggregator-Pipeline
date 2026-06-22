from collectors.epss_dataset import EPSSDataset


class EPSSCollector:

    def __init__(self):
        dataset = EPSSDataset()
        dataset.download()
        self.scores = dataset.load()

    def get_epss_score(self, cve_id):
        return self.scores.get(cve_id, 0.0)

    def fetch_incremental(self, last_sync):
        # EPSS publishes daily scores.
        # Future implementation:
        # Download daily CSV/API snapshot.
        return []
