from scheduler.pipeline_runner import PipelineRunner
from scheduler.sync_manager import SyncManager
from collectors.registry import CollectorRegistry
from storage.json_repo import JsonRepository

runner = PipelineRunner()
sync = SyncManager()
registry = CollectorRegistry()

def initial_load(cves):
    runner.process_batch(cves)

def refresh_source(source):
    last_sync = sync.get_last_sync(source)
    collector = registry.get(source)
    cves = collector.fetch_incremental(last_sync)
    if not cves:
        print(f"[{source}] No new CVEs found")
        sync.update_last_sync(source)
        return

    print(f"[{source}] {len(cves)} CVEs found")
    runner.refresh_batch(cves)
    sync.update_last_sync(source)


def refresh_all_sources():
    all_cves = set()
    sources = ["nvd", "kev", "epss", "exploitdb"]
    for source in sources:
        last_sync = sync.get_last_sync(source)
        collector = registry.get(source)

        try:
            cves = collector.fetch_incremental(last_sync)
            if cves:
                all_cves.update(cves)
            sync.update_last_sync(source)
            print(f"[{source}] {len(cves)} updated CVEs")

        except Exception as e:
            print(f"[{source}] failed:", e)

    if not all_cves:
        print("No CVEs require refresh")
        return

    print(f"Refreshing {len(all_cves)} unique CVEs")
    runner.refresh_batch(list(all_cves))


def enrichment_sync():
    repository = JsonRepository()
    cves = repository.get_all_cve_ids()
    
    print(f"Refreshing {len(cves)} stored CVEs")
    runner.refresh_batch(cves)
    sync.update_last_sync("enrichment")