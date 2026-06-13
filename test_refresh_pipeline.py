from pipeline.refresh_pipeline import RefreshPipeline

pipeline = RefreshPipeline()

record = pipeline.run("CVE-2023-5795")
# print(record)