import json
from pathlib import Path

from loader.source.cve_source import CVESource


class MITRESource(CVESource):
    def __init__(self, root):
        self.root = Path(root)

        print("MITRE Source Root:")
        print(self.root)
        print("Exists :", self.root.exists())

    def get_all(self, last_cve=None):
        resume = last_cve is None

        files = sorted(self.root.rglob("*.json"))

        print(f"Found {len(files)} JSON files")

        files.sort()

        print("Total MITRE Files :", len(files))

        for index, file in enumerate(files):
            if index % 1000 == 0:
                print(f"Scanning : {index}/{len(files)}")

            try:
                with open(file, encoding="utf-8") as f:
                    data = json.load(f)

                cve = data.get("cveMetadata", {}).get("cveId")

                if cve is None:
                    continue

                if not resume:
                    if cve == last_cve:
                        resume = True

                    continue
                yield data

            except Exception as error:
                print(error)
                continue  # nosec B112
