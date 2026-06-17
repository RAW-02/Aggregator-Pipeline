from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import time

from loader.bootstrap.mitre_bootstrap import MITREBootstrap
from loader.source.mitre_source import MITRESource

from loader.batch.batch_loader import BatchLoader
from loader.worker.mitre_worker import MitreWorker
from loader.queue.failed_queue import FailedQueue
from loader.stats.loader_stats import LoaderStats
from loader.checkpoint.checkpoint_manager import CheckpointManager

from storage.opensearch_repository import OpenSearchRepository
from config.settings import BATCH_SIZE, MAX_WORKERS

class InitialLoader:
    def __init__(self):
        self.bootstrap = MITREBootstrap()
        root = self.bootstrap.prepare()
        self.source = MITRESource(root)

        self.worker = MitreWorker()
        self.repository = OpenSearchRepository()
        self.stats = LoaderStats()
        self.failed_queue = FailedQueue()
        self.checkpoint = CheckpointManager()

    def run(self, limit=None):
        success = False
        try:
            checkpoint = self.checkpoint.load()

            iterator = tqdm(
                self.source.get_all(
                last_cve=checkpoint["last_cve"]
                ), 
                desc="Loading CVEs", unit=" CVE")

            start_time = time.time()

            processed = 0

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:

                for batch in BatchLoader.batches(iterator, batch_size=BATCH_SIZE):
                    records = []
                    batch_success = 0
                    batch_failed = 0
                
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

                    # Nothing to store
                    if not records:
                        self.stats.update(len(batch), batch_success, batch_failed)
                        self.stats.print()
                        continue

                    self.repository.bulk_upsert(records)
                    
                    self.checkpoint.save(
                        processed=self.stats.processed + batch_success,
                        last_cve=records[-1].cve_id
                    )

                    # Update statistics
                    self.stats.update(len(batch), batch_success, batch_failed)

                    processed += batch_success

                    if limit is not None and processed >= limit:
                        print()
                        print("=" * 60)
                        print(f"Reached Test Limit ({limit} CVEs)")
                        print("=" * 60)
                        break

                    elapsed = time.time() - start_time
                    rate = 0
                    if elapsed > 0:
                        rate = self.stats.processed / elapsed

                    self.stats.print()

                    print(f"Indexed : {batch_success}")
                    print(f"Failed  : {batch_failed}")
                    print(f"Rate    : {rate:.2f} CVEs/sec")
                    print()

            success = True

        finally:
            if success:
                self.bootstrap.cleanup()