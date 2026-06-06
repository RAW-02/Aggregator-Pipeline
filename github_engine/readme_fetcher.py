import requests
import base64
from github_engine.config import GITHUB_TOKEN

class ReadmeFetcher:
    README_URL = "https://api.github.com/repos"

    def fetch_readme(self, repo_name):
        headers = {"Authorization": f"Bearer {GITHUB_TOKEN}"}
        url = (f"{self.README_URL}/" f"{repo_name}/readme")
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return ""

        data = response.json()
        encoded_content = data.get("content","")

        try:
            decoded = (base64.b64decode(encoded_content).decode("utf-8", errors="ignore"))
            return decoded

        except Exception:
            return ""