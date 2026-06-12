import json
from pathlib import Path

from loader.source.cve_source import CVESource

class MITREFeedSource(CVESource):

    def __init__(self, root="database/mitre_feed/cves"):
        self.root = Path(root)

    def get_all(self, last_cve=None):
        resume = last_cve is None

        years = sorted(self.root.iterdir())

        for year in years:
            if not year.is_dir():
                continue

            for file in year.rglob("*.json"):
                try:
                    with open(file, encoding="utf-8") as f:
                        data = json.load(f)

                    cve = data["cveMetadata"]["cveId"]
                    if not resume:
                        if cve == last_cve:
                            resume = True

                        continue

                    yield data

                except Exception:
                    continue