from collectors.registry import CollectorRegistry
from scheduler.sync_manager import SyncManager

class IncrementalManager:
    def __init__(self):
        self.registry = CollectorRegistry()
        self.sync = SyncManager()

    def collect_incremental_cves(self):
        cves = set()
        sources = ["nvd", "kev", "epss", "exploitdb"]

        for source in sources:
            last_sync = self.sync.get_last_sync(source)
            collector = self.registry.get(source)

            try:
                result = collector.fetch_incremental(last_sync)
                cves.update(result)
                self.sync.update_last_sync(source)

            except Exception as e:
                print(f"{source} failed:", e)

        return list(cves)