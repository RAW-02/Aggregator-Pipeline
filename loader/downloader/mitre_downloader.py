import os
import shutil
import zipfile
import requests


class MITREDownloader:

    URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"

    ROOT = "/tmp/mitre"

    ZIP = "/tmp/mitre/cvelist.zip"

    EXTRACT = "/tmp/mitre/extracted"

    def download(self):

        os.makedirs(self.ROOT, exist_ok=True)

        print()

        print("Downloading MITRE Feed...")

        response = requests.get(

            self.URL,

            stream=True,

            timeout=600

        )

        response.raise_for_status()

        with open(self.ZIP, "wb") as file:

            for chunk in response.iter_content(1024 * 1024):

                if chunk:

                    file.write(chunk)

        print("Download Complete")

    def extract(self):

        print()

        print("Extracting Feed...")

        os.makedirs(self.EXTRACT, exist_ok=True)

        with zipfile.ZipFile(self.ZIP) as zip_file:

            zip_file.extractall(self.EXTRACT)

        print("Extraction Complete")

    def cleanup(self):

        print()

        print("Cleaning Temporary Files...")

        shutil.rmtree(

            self.ROOT,

            ignore_errors=True

        )