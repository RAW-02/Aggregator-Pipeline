import os

from loader.downloader.mitre_downloader import MITREDownloader


class MITREBootstrap:

    ROOT = "/tmp/mitre"

    ZIP = "/tmp/mitre/cvelist.zip"

    EXTRACT = "/tmp/mitre/extracted"

    def __init__(self):

        self.downloader = MITREDownloader()

    def prepare(self):

        if not os.path.exists(self.ZIP):

            print()

            print("MITRE ZIP not found")

            self.downloader.download()

        else:

            print()

            print("MITRE ZIP already exists")

        if not os.path.exists(self.EXTRACT):

            self.downloader.extract()

        else:

            print("MITRE already extracted")

        return self.EXTRACT

    def cleanup(self):

        self.downloader.cleanup()