from loader.queue.failed_queue import FailedQueue
from pipeline.aggregation_pipeline import AggregationPipeline

queue = FailedQueue()
pipeline = AggregationPipeline()

for item in queue.get_all():
    try:
        pipeline.run(item["cve"])
        print(f"Recovered {item['cve']}")

    except Exception as error:
        print(error)
        pass    # nosec B112
