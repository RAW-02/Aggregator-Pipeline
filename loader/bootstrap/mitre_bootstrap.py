import os
import tempfile
from pathlib import Path
from loader.downloader.mitre_downloader import MITREDownloader


class MITREBootstrap:
    ROOT = Path(tempfile.gettempdir()) / "mitre"
    ZIP = ROOT / "cvelist.zip"
    EXTRACT = ROOT / "extracted"

    def __init__(self):
        self.downloader = MITREDownloader()

    def prepare(self):

        print()
        print("========== MITRE Bootstrap ==========")
        print()

        print("ZIP Exists :", os.path.exists(self.ZIP))
        print("Extract Exists :", os.path.exists(self.EXTRACT))

        if not os.path.exists(self.ZIP):
            print("Downloading MITRE ZIP...")
            self.downloader.download()

        else:
            print("MITRE ZIP already exists")

        if not os.path.exists(self.EXTRACT):
            print("Extracting MITRE ZIP...")

            self.downloader.extract()

        else:
            print("MITRE already extracted")

        print()
        print("Returning Root :", self.EXTRACT)

        return self.EXTRACT

    def cleanup(self):

        self.downloader.cleanup()
