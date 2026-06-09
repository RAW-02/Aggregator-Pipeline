from collectors.mitre_collector import MITRECollector
from scheduler.sync_manager import SyncManager
from scheduler.pipeline_runner import PipelineRunner
from storage.json_repo import JsonRepository

runner = PipelineRunner()
sync = SyncManager()
mitre = MITRECollector()

def mitre_sync():
    last_sync = sync.get_last_sync("mitre")
    cves = mitre.fetch_incremental(last_sync)
    runner.process_batch(cves)
    sync.update_last_sync("mitre")

def enrichment_sync():
    repository = JsonRepository()
    cves = repository.get_all_cve_ids()
    runner.refresh_batch(cves)
    sync.update_last_sync("enrichment")