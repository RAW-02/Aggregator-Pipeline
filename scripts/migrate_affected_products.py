from collectors.nvd_dataset import NVDDataset
from storage.opensearch_repository import OpenSearchRepository

BATCH_SIZE = 1000


def main():

    print("=" * 60)
    print("Loading NVD Cache")
    print("=" * 60)

    cache = NVDDataset().load()

    repository = OpenSearchRepository()

    print(f"Total CVEs in cache : {len(cache)}")
    print()

    updates = []

    updated = 0
    missing = 0

    for cve_id, nvd in cache.items():

        affected_products = nvd.get("affected_products")

        if affected_products is None:
            continue

        updates.append(
            {
                "cve_id": cve_id,
                "fields": {"affected_products": affected_products},
            }
        )

        if len(updates) >= BATCH_SIZE:
            success, errors = repository.bulk_update(updates)

            updated += success
            missing += len(errors)

            print(
                f"Updated: {updated} | "
                f"Failed: {len(errors)} | "
                f"Total Errors: {missing}"
            )

            updates.clear()

    if updates:

        success, errors = repository.bulk_update(updates)

        updated += success
        missing += len(errors)

    print()
    print("=" * 60)
    print("Migration Completed")
    print("=" * 60)
    print("Updated :", updated)
    print("Missing :", missing)


if __name__ == "__main__":
    main()
