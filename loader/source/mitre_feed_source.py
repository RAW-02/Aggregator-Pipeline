import json
from pathlib import Path
from loader.source.cve_source import CVESource

class MITREFeedSource(CVESource):
    def __init__(self, root="database/mitre_feed/cves"):
        self.root = Path(root)

    def get_all(self, last_cve=None):
        resume = last_cve is None

        # build list once
        files = sorted(self.root.rglob("*.json"))
        print(f"Total MITRE files found : {len(files)}")

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
                continue    # nosec B112
