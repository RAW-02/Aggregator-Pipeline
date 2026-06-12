from scheduler.pipeline_runner import PipelineRunner

runner = PipelineRunner()

res = runner.refresh_batch(
    [
        "CVE-2024-33849",
        "CVE-2024-3400",
    ]
)