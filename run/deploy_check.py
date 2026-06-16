from storage.opensearch_repository import OpenSearchRepository

repo = OpenSearchRepository()

print("Connection OK")

print("Documents :", repo.count())