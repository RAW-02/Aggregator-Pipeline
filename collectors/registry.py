from collectors.epss_collector import EPSSCollector
from collectors.exploitdb_collector import ExploitDBCollector
from collectors.kve_collector import KEVCollector
from collectors.mitre_collector import MITRECollector
from collectors.nvd_collector import NVDCollector


class CollectorRegistry:
    def __init__(self):
        self.collectors = {
            "mitre": MITRECollector(),
            "nvd": NVDCollector(),
            "kev": KEVCollector(),
            "epss": EPSSCollector(),
            "exploitdb": ExploitDBCollector(),
        }

    def get(self, name):
        return self.collectors[name]

    def refresh(self, source, last_sync):
        return self.collectors[source].fetch_incremental(last_sync)
