import json
import os
import time
import requests
from config.settings import NVD_API_KEY
from normalizer.nvd_normalizer import NVDDataNormalizer

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

CACHE_PATH = "database/nvd_cache.json"

PAGE_SIZE = 500
CHECKPOINT_INTERVAL = 5000
MAX_RETRIES = 5


def save_cache(cache):

    os.makedirs("database", exist_ok=True)

    with open(CACHE_PATH, "w", encoding="utf-8") as file:

        json.dump(cache, file)


def load_cache():

    if not os.path.exists(CACHE_PATH):
        return {}

    if os.path.getsize(CACHE_PATH) == 0:
        return {}

    with open(CACHE_PATH, "r", encoding="utf-8") as file:

        return json.load(file)


def request_page(headers, start_index):

    for attempt in range(MAX_RETRIES):

        try:

            response = requests.get(
                NVD_URL,
                params={"startIndex": start_index, "resultsPerPage": PAGE_SIZE},
                headers=headers,
                timeout=120,
            )

            response.raise_for_status()

            return response.json()

        except Exception as e:

            print(
                f"[Retry {attempt + 1}/{MAX_RETRIES}] "
                f"startIndex={start_index} : {e}"
            )

            time.sleep(5)

    raise Exception(f"Failed after {MAX_RETRIES} retries")


def build_cache():

    api_key = NVD_API_KEY

    if not api_key:
        raise Exception("NVD_API_KEY not configured in settings.py")

    headers = {"apiKey": api_key, "User-Agent": "UniVulner"}

    normalizer = NVDDataNormalizer()

    cache = load_cache()

    start_index = len(cache)

    if cache:
        print(f"Resuming from {len(cache)} cached CVEs")
    else:
        print("Starting fresh NVD cache build")

    total_results = None

    while True:

        print()
        print(f"Downloading startIndex={start_index}")

        data = request_page(headers, start_index)

        total_results = data["totalResults"]

        vulnerabilities = data.get("vulnerabilities", [])

        print(f"Received {len(vulnerabilities)} records")

        if not vulnerabilities:
            break

        for item in vulnerabilities:

            try:

                cve_id = item["cve"]["id"]

                result = normalizer.get_result(item)

                cache[cve_id] = {
                    "cvss_score": result.cvss_score,
                    "severity": result.severity,
                    "cwe": result.cwe,
                    "products": result.affected_products,
                }

            except Exception as e:

                print("Failed:", item.get("cve", {}).get("id", "UNKNOWN"), e)

        print(f"Cached {len(cache)} / {total_results}")

        if len(cache) > 0 and len(cache) % CHECKPOINT_INTERVAL == 0:

            print()
            print(f"Checkpoint Save " f"({len(cache)} CVEs)")

            save_cache(cache)

        start_index += PAGE_SIZE

        if start_index >= total_results:
            break

        time.sleep(1)

    print()
    print("Final Cache Save")

    save_cache(cache)

    print()
    print("=" * 60)
    print("NVD CACHE COMPLETE")
    print("=" * 60)
    print(f"Total Cached: {len(cache)}")


if __name__ == "__main__":
    build_cache()


# from config.settings import NVD_API_KEY

# print("NVD_API_KEY =", NVD_API_KEY)