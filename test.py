from pipeline.aggregation_pipeline import AggregationPipeline

pipeline = AggregationPipeline()
record = pipeline.run("CVE-2021-44228")
print(record)


# Batch / Bulk CVE Processing
# from scheduler.pipeline_runner import PipelineRunner
# runner = PipelineRunner()
# runner.process_batch(
#     [
#         "CVE-2026-9412",
#         "CVE-2026-9057",
#         "CVE-2024-3094"
#     ]
# )