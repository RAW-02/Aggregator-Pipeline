import gzip
import csv
import requests
from pathlib import Path


class EPSSDataset:
    URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    FILE = Path("database/epss/epss.csv.gz")

    def download(self):
        self.FILE.parent.mkdir(parents=True, exist_ok=True)

        print("Downloading EPSS Dataset...")

        response = requests.get(self.URL, stream=True, timeout=300)
        response.raise_for_status()

        with open(self.FILE, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        print("EPSS Download Complete")

    def load(self):
        scores = {}

        with gzip.open(self.FILE, "rt", encoding="utf-8") as f:
            next(f)

            reader = csv.DictReader(f)

            for row in reader:
                scores[row["cve"]] = float(row["epss"])

        return scores
