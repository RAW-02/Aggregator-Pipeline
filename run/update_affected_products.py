from collectors.nvd_collector import NVDCollector
from storage.opensearch_repository import OpenSearchRepository

BATCH_SIZE = 1000


def main():

    print("=" * 60)
    print("Updating affected_products")
    print("=" * 60)

    repository = OpenSearchRepository()
    collector = NVDCollector()

    updates = []
    updated = 0

    for record in repository.get_all():
        cve_id = record["cve_id"]
        result = collector.get_nvd_by_cve(cve_id)

        if result is None:
            continue

        updates.append(
            {
                "cve_id": cve_id,
                "fields": {"affected_products": result.get("affected_products", [])},
            }
        )

        if len(updates) >= BATCH_SIZE:
            repository.bulk_update(updates)
            updated += len(updates)
            print(f"Updated : {updated}")
            updates.clear()

    if updates:
        repository.bulk_update(updates)
        updated += len(updates)

    print()
    print("=" * 60)
    print("Completed")
    print("=" * 60)
    print(f"Updated : {updated}")


if __name__ == "__main__":
    main()
