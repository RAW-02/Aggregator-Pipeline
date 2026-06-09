from pipeline.refresh_pipeline import RefreshPipeline

pipeline = RefreshPipeline()

record = pipeline.run("CVE-2026-5795")
print(record)