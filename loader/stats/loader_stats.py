from dataclasses import dataclass


@dataclass
class LoaderStats:
    total: int = 0
    processed: int = 0
    success: int = 0
    failed: int = 0
    batches: int = 0

    def update(self, batch_size, success_count, failed_count):
        self.batches += 1
        self.total += batch_size
        self.processed += batch_size
        self.success += success_count
        self.failed += failed_count

    def print(self):
        print()
        print("=" * 60)
        print(f"Batch           : {self.batches}")
        print(f"Processed       : {self.processed}")
        print(f"Success         : {self.success}")
        print(f"Failed          : {self.failed}")

        if self.processed:
            percentage = round(self.success / self.processed * 100, 2)
            print(f"Success Rate    : {percentage}%")

        print("=" * 60)