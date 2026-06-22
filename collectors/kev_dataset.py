import requests


class KEVDataset:
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"  # noqa: F401, E501

    def load(self):
        print("Downloading KEV Dataset...")

        response = requests.get(self.URL, timeout=60)
        response.raise_for_status()

        data = response.json()
        kev_set = set()

        for item in data["vulnerabilities"]:
            kev_set.add(item["cveID"])

        print(f"Loaded KEV : {len(kev_set)}")

        return kev_set
