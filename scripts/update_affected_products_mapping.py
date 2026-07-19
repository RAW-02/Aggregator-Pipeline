import os
from storage.opensearch_client import OpenSearchClient


def main():
    client = OpenSearchClient().get_client()
    index = os.getenv("OPENSEARCH_INDEX", "vulnerabilities")

    client.indices.put_mapping(
        index=index,
        body={
            "properties": {
                "affected_products": {
                    "type": "nested",
                    "properties": {
                        "vendor": {"type": "keyword"},
                        "product": {"type": "keyword"},
                        "version_start_including": {"type": "keyword"},
                        "version_start_excluding": {"type": "keyword"},
                        "version_end_including": {"type": "keyword"},
                        "version_end_excluding": {"type": "keyword"},
                    },
                }
            }
        },
    )

    print("✓ affected_products mapping added.")


if __name__ == "__main__":
    main()
