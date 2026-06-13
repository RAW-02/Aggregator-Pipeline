import json
import os


class PendingIndex:

    def __init__(self):

        self.directory = "database/index"

        os.makedirs(self.directory, exist_ok=True)

        self.cache = {}

    def _path(self, source):

        return os.path.join(
            self.directory,
            f"{source}.json"
        )

    def load(self, source):

        if source in self.cache:

            return self.cache[source]

        path = self._path(source)

        if not os.path.exists(path):

            self.cache[source] = set()

            return self.cache[source]

        with open(path, "r") as f:

            data = set(json.load(f))

        self.cache[source] = data

        return data

    def save(self, source):

        with open(self._path(source), "w") as f:

            json.dump(
                sorted(list(self.cache[source])),
                f,
                indent=4
            )

    def add(self, source, cve):

        records = self.load(source)

        records.add(cve)

    def remove(self, source, cve):

        records = self.load(source)

        records.discard(cve)

    def flush(self):

        for source in self.cache:

            self.save(source)