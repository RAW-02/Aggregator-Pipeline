from concurrent.futures import ThreadPoolExecutor

from loader.batch.batch_loader import BatchLoader
from loader.source.mitre_feed_source import MITREFeedSource
from loader.worker.worker import Worker
from loader.queue.failed_queue import FailedQueue
from loader.stats.loader_stats import LoaderStats
from loader.checkpoint.checkpoint_manager import CheckpointManager
from storage.json_repo import JsonRepository

class InitialLoader:
    def __init__(self):
        self.source = MITREFeedSource()
        self.worker = Worker()
        self.repository = JsonRepository()
        self.stats = LoaderStats()
        self.failed_queue = FailedQueue()
        self.checkpoint = CheckpointManager()

    def run(self):
        checkpoint = self.checkpoint.load()

        iterator = self.source.get_all(
            last_cve=checkpoint["last_cve"]
        )

        for batch in BatchLoader.batches(iterator, batch_size=10):
            records = []
            batch_success = 0
            batch_failed = 0

            with ThreadPoolExecutor(max_workers=10) as executor:
                results = list(executor.map(self.worker.process, batch))

            for mitre_json, result in zip(batch, results):
                record, error = result
                if error is not None:
                    batch_failed += 1
                    cve = mitre_json.get("cveMetadata", {}).get("cveId")
                    self.failed_queue.add(cve, str(error))
                    continue
                if record is None:
                    batch_failed += 1
                    continue
                
                batch_success += 1
                records.append(record)

            self.repository.bulk_upsert(records)
            
            if records:
                last = records[-1]
                last_cve = last.cve_id if hasattr(last, "cve_id") else last["cve_id"]
                self.checkpoint.save(
                    processed=self.stats.processed,
                    last_cve=last_cve
                )

            self.stats.update(len(batch), batch_success, batch_failed)

            self.stats.print()