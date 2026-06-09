from pipeline.aggregation_pipeline import AggregationPipeline

pipeline = AggregationPipeline()
record = pipeline.run("CVE-2024-33849")

# Batch / Bulk CVE Processing
# from scheduler.pipeline_runner import PipelineRunner
# runner = PipelineRunner()
# runner.process_batch(
#     [
#         "CVE-2026-49053",
#         "CVE-2026-49047",
#         "CVE-2026-49782"
#     ]
# )