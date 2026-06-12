# from pipeline.aggregation_pipeline import AggregationPipeline

# pipeline = AggregationPipeline()
# record = pipeline.run("CVE-2024-33859")

# Batch / Bulk CVE Processing
from scheduler.pipeline_runner import PipelineRunner
runner = PipelineRunner()
runner.process_batch(
    [
        "CVE-2026-49050",
        "CVE-2026-49051",
        "CVE-2026-49752"
    ]
)