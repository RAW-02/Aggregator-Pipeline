from storage.json_repo import JsonRepository

# later

# from storage.opensearch_repo import OpenSearchRepository


class MigrationTool:

    def __init__(self):

        self.json_repo = JsonRepository()

        # self.opensearch = OpenSearchRepository()

    def migrate(self):

        records = self.json_repo.get_all()

        print()

        print("Total Records :", len(records))

        print()

        batch = []

        for record in records:

            batch.append(record)

            if len(batch) == 1000:

                # self.opensearch.bulk_upsert(batch)

                print("Migrated :", len(batch))

                batch.clear()

        if batch:

            # self.opensearch.bulk_upsert(batch)

            print("Migrated :", len(batch))


if __name__ == "__main__":

    MigrationTool().migrate()