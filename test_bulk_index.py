from pipeline.aggregation_pipeline import AggregationPipeline

pipeline = AggregationPipeline()

cves = [
    "CVE-2014-6271",
    "CVE-2021-44228",
    "CVE-2021-26855",
    "CVE-2023-23397",
    "CVE-2024-3400",
    "CVE-2024-21762",
    "CVE-2024-27198",
    "CVE-2024-1709",
    "CVE-2024-6387",
    "CVE-2024-33849"
]

for cve in cves:
    try:
        pipeline.run(cve)
        print(f"Indexed {cve}")
    except Exception as e:
        print(f"Failed {cve}: {e}")