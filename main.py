from pipeline.vulnerability_aggregator import VulnerabilityAggregator
# from storage.elastic_repo import ElasticRepository
from storage.json_repo import JsonRepository

# repo = ElasticRepository()
repo = JsonRepository()
# repo.create_index()

aggregator = VulnerabilityAggregator()
record = aggregator.aggregate("CVE-2014-6271")

# Insert Single Data in Database 
# ----------------------------------------------
repo.upsert(record)
print("Stored Successfully")


# Search Data
# ----------------------------------------------
# print(repo.search("bash"))


# Insert Bulk Data in Databse
# ----------------------------------------------
# records = []
# for cve in cve_list:
#     record = aggregator.aggregate(cve)
#     records.append(record)
# repo.bulk_upsert(records)
# print("Stored Successfully")