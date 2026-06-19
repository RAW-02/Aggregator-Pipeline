from itertools import islice


class BatchLoader:
    @staticmethod
    def batches(iterator, batch_size):
        iterator = iter(iterator)

        while True:
            batch = list(islice(iterator, batch_size))

            if not batch:
                break

            yield batch
